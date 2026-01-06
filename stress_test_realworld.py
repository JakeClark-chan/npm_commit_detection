
import os
import sys
import json
import time
import subprocess
import shutil
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from tqdm import tqdm
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
import tiktoken

# Import project modules
# Assumes the script is run from the project root or the same directory as stress_test.py
sys.path.append(os.getcwd())

from analyzers.pre_analysis import Repository
from llm.static_analysis import StaticAnalyzer
from llm.service import LLMService
from configs.static_config import StaticAnalysisConfig

# Setup logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# Constants
REALWORLD_LIST_FILE = "list-of-realworld-repo.json"
REPORT_FILE = "realworld_stress_test_report.md"
TMP_DIR = "/tmp/npm_commit_detection_stress_test" # Use system tmp as requested
MAX_WORKERS_PER_REPO = 8
MAX_TOKENS_LIMIT = 100000  # Skip verification if prompt exceeds this

# Token counter (use cl100k_base which works for most models)
try:
    TOKEN_ENCODER = tiktoken.get_encoding("cl100k_base")
except:
    TOKEN_ENCODER = None

def load_repo_list(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data.get("repositories", [])

def cleanup_tmp_dir(path: str):
    if os.path.exists(path):
        try:
            shutil.rmtree(path)
        except Exception as e:
            logger.error(f"Failed to cleanup {path}: {e}")

def get_all_commits(repo_path: str) -> List[str]:
    try:
        cmd = ["git", "-C", repo_path, "log", "--pretty=format:%H"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return [c.strip() for c in result.stdout.split('\n') if c.strip()]
    except subprocess.CalledProcessError as e:
        logger.error(f"Error getting commits for {repo_path}: {e}")
        return []

def clone_repo(url: str, dest_path: str) -> bool:
    try:
        if os.path.exists(dest_path):
            cleanup_tmp_dir(dest_path)
        
        # Using depth 1 might not get all history if we want *all* commits history? 
        # User said "scan all commits of the repo".
        # So full clone is necessary.
        # Ensure we don't run any hooks (though clone usually doesn't).
        # We are strictly cloning for static analysis.
        subprocess.run(["git", "clone", url, dest_path], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone {url}: {e}")
        return False

def simple_verification(commit_sha, static_json, pre_analysis=None):
    """
    Simplified verification using static analysis results and pre-analysis data.
    """
    model_name = StaticAnalysisConfig.MODEL
    llm = LLMService.get_llm(model_name=model_name, temperature=0.0)
    
    # Dynamic analysis is skipped, so pass empty or "skipped" info
    dynamic_json = {"status": "skipped", "reason": "Real-world stress test: Dynamic analysis skipped"}
    
    # Format pre-analysis data if available
    pre_analysis_text = ""
    if pre_analysis:
        pre_analysis_text = f"""
    Pre-Analysis (Repository & Commit Metadata):
    - Repository: {pre_analysis.get('repo_name', 'Unknown')}
    - Author: {pre_analysis.get('author', 'Unknown')}
    - Date: {pre_analysis.get('date', 'Unknown')}
    - Message: {pre_analysis.get('message', 'No message')}
    - Files Changed: {pre_analysis.get('files_changed', 0)}
    """

    prompt = f"""
    You are a security expert. Analyze the following reports for commit {commit_sha} and determine if it is benign or malware.
    {pre_analysis_text}
    Static Analysis:
    {json.dumps(static_json, indent=2)}
    
    Dynamic Analysis:
    {json.dumps(dynamic_json, indent=2)}
    
    With all analysis from static and dynamic is this commit benign or malware?
    
    Provide your response in JSON format with the following structure:
    {{
        "verdict": "MALWARE" or "BENIGN",
        "findings": [
            {{
                "file": "file path",
                "code": "relevant code snippet",
                "reason": "explanation of why this specific part is suspicious/safe"
            }}
        ],
        "general_reason": "Overall summary of the decision"
    }}
    output only the json.
    """
    
    # Check token count and skip if too large
    if TOKEN_ENCODER:
        token_count = len(TOKEN_ENCODER.encode(prompt))
        if token_count > MAX_TOKENS_LIMIT:
            logger.warning(f"Skipping {commit_sha}: prompt too large ({token_count} tokens > {MAX_TOKENS_LIMIT})")
            return "benign", f"Skipped: Prompt too large ({token_count} tokens). Likely initial/merge commit."
    
    messages = [
        SystemMessage(content="You are a security expert. Output only valid JSON."),
        HumanMessage(content=prompt)
    ]
    
    try:
        response = llm.invoke(messages)
        content = (response.content or "").strip()
        
        # Remove markdown code blocks if present
        if content.startswith("```json"):
            content = content[7:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()
        
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            import re
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match:
                data = json.loads(match.group(0))
            else:
                raise ValueError("Could not parse JSON response")

        verdict = data.get("verdict", "unknown").lower()
        
        lines = []
        findings = data.get("findings", [])
        general_reason = data.get("general_reason", "")
        
        for f in findings:
            file_path = f.get("file", "Unknown file")
            code = (f.get("code") or "").strip()
            reason = (f.get("reason") or "").strip()
            
            lines.append(f"**File {file_path}**:")
            if code:
                code_snippet = code.replace('\n', ' ')[:200]
                lines.append(f"Code: `{code_snippet}`")
            lines.append(f"Reason: {reason}")
            lines.append("")
            
        if general_reason:
            lines.append(f"**Summary:** {general_reason}")
            
        explanation = "\n".join(lines).strip()
        if not explanation:
            explanation = "No detailed findings provided."
            
        return verdict, explanation
        
    except Exception as e:
        logger.error(f"LLM verification failed for {commit_sha}: {e}")
        return "unknown", f"Analysis failed: {e}"

def analyze_commit(commit_sha: str, repo_path: str) -> Dict[str, Any]:
    analysis_start = time.time()
    result = {
        "commit": commit_sha,
        "static_time": 0.0,
        "verification_time": 0.0,
        "total_time": 0.0,
        "verdict": "unknown",
        "explanation": "",
        "repo_path": repo_path
    }
    
    try:
        repo = Repository(repo_path)
        analyzer = StaticAnalyzer() 
        
        # Static Analysis
        static_start = time.time()
        static_output = analyzer.analyze_commits(repo, [commit_sha])
        result["static_time"] = time.time() - static_start
        
        issues_list = []
        if 'all_issues' in static_output:
            for issue in static_output['all_issues']:
                issues_list.append({
                    'severity': issue.severity,
                    'category': issue.category,
                    'description': issue.description,
                    'file_path': issue.file_path,
                    'recommendation': issue.recommendation
                })
        
        static_res = {
            'total_issues': static_output.get('total_issues', 0),
            'issues': issues_list
        }
        
        # Verification
        if static_res['total_issues'] > 0:
            # Gather pre-analysis data (repo-level + commit metadata, no diff)
            try:
                metadata = repo.get_commit_metadata(commit_sha)
                file_changes = repo.get_file_changes(commit_sha)
                pre_analysis = {
                    'repo_name': repo.name,
                    'author': f"{metadata.author_name} <{metadata.author_email}>",
                    'date': str(metadata.date),
                    'message': metadata.message,
                    'files_changed': len(file_changes)
                }
            except Exception as e:
                logger.warning(f"Could not get pre-analysis for {commit_sha}: {e}")
                pre_analysis = None
            
            verif_start = time.time()
            verdict, explanation = simple_verification(commit_sha, static_res, pre_analysis)
            result["verification_time"] = time.time() - verif_start
            result["verdict"] = verdict
            result["explanation"] = explanation
        else:
            result["verdict"] = "benign"
            result["explanation"] = "No static analysis issues found."
            
    except Exception as e:
        logger.error(f"Analysis failed for {commit_sha}: {e}")
        result["explanation"] = f"Error: {str(e)}"
        
    result["total_time"] = time.time() - analysis_start
    return result

def main():
    if not os.path.exists(REALWORLD_LIST_FILE):
        print(f"Error: Input file {REALWORLD_LIST_FILE} not found.")
        return

    repo_urls = load_repo_list(REALWORLD_LIST_FILE)
    print(f"Loaded {len(repo_urls)} repositories.")
    
    os.makedirs(TMP_DIR, exist_ok=True)
    
    all_results = []
    
    # Checkpoint/Partial save setup could be added here if needed
    
    for url in tqdm(repo_urls, desc="Processing Repositories"):
        repo_name = url.rstrip("/").split("/")[-1]
        if not repo_name:
            continue
            
        repo_path = os.path.abspath(os.path.join(TMP_DIR, repo_name))
        
        print(f"\nCloning {url} to {repo_path}...")
        if not clone_repo(url, repo_path):
            continue
            
        commits = get_all_commits(repo_path)
        print(f"Scanning {len(commits)} commits in {repo_name}...")
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_PER_REPO) as executor:
            future_to_commit = {executor.submit(analyze_commit, commit, repo_path): commit for commit in commits}
            
            for future in tqdm(as_completed(future_to_commit), total=len(commits), desc=f"Analyzing {repo_name}", leave=False):
                try:
                    res = future.result()
                    res['repo_url'] = url # Add repo URL to result
                    all_results.append(res)
                except Exception as e:
                    logger.error(f"Commit analysis failed: {e}")
                    
        # Cleanup repo to save space
        cleanup_tmp_dir(repo_path)

    # Generate Report
    generate_report(all_results)
    print(f"Analysis complete. Report saved to {REPORT_FILE}")

def generate_report(results: List[Dict[str, Any]]):
    malware_count = len([r for r in results if r['verdict'] == 'malware'])
    benign_count = len([r for r in results if r['verdict'] == 'benign'])
    
    # Timing stats
    static_times = [r['static_time'] for r in results]
    verif_times = [r['verification_time'] for r in results]
    total_times = [r['total_time'] for r in results]
    
    def safe_stats(data):
        if not data: return 0, 0, 0, 0
        return max(data), min(data), sum(data)/len(data), sum(data)

    max_s, min_s, avg_s, total_s = safe_stats(static_times)
    max_v, min_v, avg_v, total_v = safe_stats(verif_times)
    max_t, min_t, avg_t, total_t = safe_stats(total_times)

    with open(REPORT_FILE, 'w') as f:
        f.write("# Stress Test Report (Real-World Repos)\n\n")
        f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Statistics\n")
        f.write(f"- Total Repositories Analyzed: {len(set(r['repo_url'] for r in results))}\n")
        f.write(f"- Total Commits Analyzed: {len(results)}\n")
        f.write(f"- Malware Found: {malware_count}\n")
        f.write(f"- Benign Found: {benign_count}\n")
        
        f.write("\n## Timing Statistics (Seconds)\n")
        f.write("| Metric | Max | Min | Average | Total |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        f.write(f"| Static Analysis Time | {max_s:.4f}s | {min_s:.4f}s | {avg_s:.4f}s | {total_s:.2f}s |\n")
        f.write(f"| Verification Time | {max_v:.4f}s | {min_v:.4f}s | {avg_v:.4f}s | {total_v:.2f}s |\n")
        f.write(f"| Total Per Commit | {max_t:.4f}s | {min_t:.4f}s | {avg_t:.4f}s | {total_t:.2f}s |\n")
        
        f.write("\n## Detailed Findings\n")
        
        # Group by Repo
        results_by_repo = {}
        for r in results:
            if r['repo_url'] not in results_by_repo:
                results_by_repo[r['repo_url']] = []
            results_by_repo[r['repo_url']].append(r)
            
        for repo_url, repo_results in results_by_repo.items():
            malware_commits = [r for r in repo_results if r['verdict'] == 'malware']
            if not malware_commits:
                continue
                
            f.write(f"### Repository: {repo_url}\n")
            f.write(f"**Verdict:** MALWARE\n\n")
            for r in malware_commits:
                f.write(f"#### Commit {r['commit'][:8]}\n")
                f.write(f"{r['explanation']}\n\n")

if __name__ == "__main__":
    load_dotenv()
    main()
