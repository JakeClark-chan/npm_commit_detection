import os
import sys
import json
import time
import subprocess
from pathlib import Path
from dotenv import load_dotenv
import signal
import requests
import requests
import glob
import argparse
import contextlib
import io
import logging
from tqdm import tqdm
import statistics

load_dotenv()

# Set up environment variables
os.environ["LANGCHAIN_TRACING_V2"] = "false" # Force disable to prevent rate limits
os.environ["CONCURRENT_THREADS"] = "8" # Ensure this is set before imports

# Import our tools
sys.path.append(os.getcwd())

from analyzers.pre_analysis import Repository
from llm.static_analysis import StaticAnalyzer
from tools.dynamic_analysis import DynamicAnalyzer
from llm.service import LLMService
from llm.verification import VerificationAnalyzer, DynamicAnalysisParser, VerificationResult
from configs.static_config import StaticAnalysisConfig
from langchain_core.messages import HumanMessage, SystemMessage

REPO_PATH = "../collection_of_attacked_repo/mongoose"
VERSION_TAG = "8.19.5"
PREV_TAG = "8.19.4"
PREDICTED_COMMITS_FILE = "predicted_commits.json"
REPORT_FILE = "stress_test_report.md"
CACHE_FILE = "all_dynamic_report.json"

def recalculate_empty_dynamic(num_commits):
    """Recalculate empty dynamic count from actual report files"""
    report_files = glob.glob('reports/dynamic_report_*.json')
    report_files.sort(key=os.path.getmtime, reverse=True)
    latest_reports = report_files[:num_commits]
    
    empty_count = 0
    for report_path in latest_reports:
        try:
            with open(report_path, 'r') as f:
                data = json.load(f)
            
            # Case 1: "status": "finished" and "result": []
            if data.get('status') == 'finished' and isinstance(data.get('result'), list) and not data.get('result'):
                empty_count += 1
            # Case 2: Generic error or empty dict
            elif not data or 'error' in data:
                empty_count += 1
        except Exception:
            empty_count += 1  # Count read errors as empty
    
    return empty_count

def calculate_accuracy_metrics(predictions):
    """Calculate accuracy metrics against truth file"""
    truth_file = 'truth_commits.json'
    if not os.path.exists(truth_file):
        truth_file = 'truth_subset_commits.json'
        
    if not os.path.exists(truth_file):
        return None
        
    try:
        with open(truth_file, 'r') as f:
            truth = json.load(f)
            
        truth_map = {item['hash']: item['label'] for item in truth}
        
        tp = fp = tn = fn = unknown = missing = 0
        
        for pred in predictions:
            h = pred['hash']
            p_label = pred['predict']
            
            if h not in truth_map:
                missing += 1
                continue
                
            t_label = truth_map[h]
            
            if p_label == 'malware':
                if t_label == 'malware': tp += 1
                else: fp += 1
            elif p_label == 'benign':
                if t_label == 'benign': tn += 1
                else: fn += 1
            else:
                unknown += 1
                
        total_eval = tp + fp + tn + fn
        if total_eval == 0:
            return None
            
        acc = (tp + tn) / total_eval
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
        
        return {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
            "missing": missing, "unknown": unknown, "total_eval": total_eval
        }
    except Exception as e:
        print(f"Error checking accuracy: {e}")
        return None

def calculate_timing_stats(timings):
    """Calculate statistics from timings list"""
    if not timings:
        return None
        
    keys = ['pre_analysis_time', 'static_analysis_time', 'dynamic_analysis_time', 'verification_time']
    stats = {}
    
    # Calculate totals per phase
    totals = {k: sum(d.get(k, 0) for d in timings) for k in keys}
    
    # Calculate total per (successful) commit
    # Note: Using sum of all phases for each commit
    total_per_commit = []
    for d in timings:
        t = sum(d.get(k, 0) for k in keys)
        total_per_commit.append(t)
        
    overall_total = sum(total_per_commit)
    
    def get_stat(values):
        if not values: return {'max':0, 'min':0, 'avg':0, 'total':0}
        
        # Check if all values are 'cached' (or effectively 0 due to cache) 
        # But here values are numbers. 
        # If we want to show 'cached' in report, we should handle it in the report generation 
        # or special case here. For now let's keep it numeric 0.0 for calculations
        # and handle display logic later.
        return {
            'max': max(values),
            'min': min(values),
            'avg': statistics.mean(values),
            'total': sum(values)
        }

    for k in keys:
        values = [d.get(k, 0) for d in timings]
        stats[k] = get_stat(values)
        
    stats['total_per_commit'] = get_stat(total_per_commit)
    stats['overall_wall_clock'] = overall_total
    
    return stats

def get_commits(repo_path, from_tag, to_tag):
    try:
        subprocess.run(["git", "-C", repo_path, "rev-parse", from_tag], check=True, capture_output=True)
        subprocess.run(["git", "-C", repo_path, "rev-parse", to_tag], check=True, capture_output=True)
        cmd = ["git", "-C", repo_path, "log", f"{from_tag}..{to_tag}", "--pretty=format:%H"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        commits = result.stdout.strip().split('\n')
        return [c.strip() for c in commits if c.strip()]
    except subprocess.CalledProcessError as e:
        print(f"Error getting commits: {e}")
        return []

def cleanup_repo(repo_path):
    """Clean up git repo state to avoid 'resolve index' errors"""
    try:
        # Reset to HEAD to clear any staging area mess from failed merges/checkouts
        subprocess.run(["git", "-C", repo_path, "reset", "--hard"], check=False, capture_output=True)
        subprocess.run(["git", "-C", repo_path, "clean", "-fd"], check=False, capture_output=True)
    except Exception as e:
        print(f"Warning: Failed to cleanup repo: {e}")

def simple_verification(commit_sha, static_json, dynamic_json):
    """Legacy simple verification - single LLM call"""
    model_name = StaticAnalysisConfig.MODEL
    llm = LLMService.get_llm(model_name=model_name, temperature=0.0)
    
    prompt = f"""
    You are a security expert. Analyze the following reports for commit {commit_sha} and determine if it is benign or malware.
    
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
            # Fallback: try to find json block
            import re
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match:
                data = json.loads(match.group(0))
            else:
                raise ValueError("Could not parse JSON response")

        verdict = data.get("verdict", "unknown").lower()
        
        # Format explanation string
        lines = []
        findings = data.get("findings", [])
        general_reason = data.get("general_reason", "")
        
        for f in findings:
            file_path = f.get("file", "Unknown file")

            code = (f.get("code") or "").strip()
            reason = (f.get("reason") or "").strip()
            
            lines.append(f"**File {file_path}**:")
            if code:
                # Truncate if too long (200 chars)
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
        print(f"LLM invocation failed: {e}")
        return "unknown", f"Analysis failed: {e}"

def advanced_verification(commit_sha, static_output, dynamic_report_path):
    """
    Advanced verification using VerificationAnalyzer
    - Normalizes static and dynamic findings
    - Uses LLM to correlate findings across tools
    - Returns verdict based on evidence matching
    """
    try:
        verifier = VerificationAnalyzer()
        
        # Normalize static findings
        static_findings = verifier.normalize_static_findings(static_output)
        
        # Parse and normalize dynamic findings
        dynamic_events = []
        if dynamic_report_path and os.path.exists(dynamic_report_path):
            parser = DynamicAnalysisParser()
            dynamic_events = parser.parse_package_hunter_log(dynamic_report_path)
        dynamic_findings = verifier.normalize_dynamic_findings(dynamic_events)
        
        # Compare findings
        result = verifier.compare_findings(static_findings, dynamic_findings, snyk_findings=None)
        
        # Determine verdict
        if result.is_malicious:
            return "malware"
        
        # If no confirmed malicious matches but high-severity unverified findings exist
        high_sev_static = any(f.severity in ['HIGH', 'CRITICAL'] for f in result.suspicious_static_only)
        high_sev_dynamic = any(f.severity in ['HIGH', 'CRITICAL'] for f in result.suspicious_dynamic_only)
        
        if high_sev_static or high_sev_dynamic:
            return "malware", result  # Conservative: flag high-severity unverified as malware
        
        return "benign", result
        
    except Exception as e:
        print(f"  Advanced verification failed: {e}")
        import traceback
        traceback.print_exc()
        return "unknown", None

def format_verification_explanation(result: VerificationResult) -> str:
    """Format verification result into detailed explanation string"""
    if not result:
        return "<No details available>"
        
    lines = []
    
    # 1. Matched Findings (Highest Confidence)
    matches = result.static_dynamic_matches + result.static_snyk_matches + result.snyk_dynamic_matches
    for f1, f2 in matches:
        # Prefer static finding for file/line info if available
        base = f1 if f1.source == 'static' else f2
        file_path = base.file_path or "Unknown file"
        line_num = base.line_number or "?"
        
        lines.append(f"**At line {line_num} file {file_path}**:")
        if base.evidence:
             # Truncate evidence if too long
             evidence = base.evidence.strip()[:200].replace('\n', ' ')
             lines.append(f"Code: `{evidence}`")
             
        lines.append(f"Reason: {base.description}")
        lines.append(f"Confirmed by {f2.source}: {f2.description}")
        lines.append("")

    # 2. Unmatched High Severity
    suspicious = [f for f in result.suspicious_static_only if f.severity in ['HIGH', 'CRITICAL']]
    suspicious += [f for f in result.suspicious_dynamic_only if f.severity in ['HIGH', 'CRITICAL']]
    
    for f in suspicious:
        file_path = f.file_path or "Unknown file"
        line_num = f.line_number or "?"
        
        lines.append(f"**At line {line_num} file {file_path}**:")
        if f.evidence:
             evidence = f.evidence.strip()[:200].replace('\n', ' ')
             lines.append(f"Code: `{evidence}`")
        
        lines.append(f"Reason: [{f.source.upper()}] {f.description}")
        lines.append("")
        
    if not lines:
        return "No significant issues detailed."
        
    return "\n".join(lines).strip()

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Stress Test Commit Detection")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Configure logging
    if not args.verbose:
        # Silence all loggers except for critical errors
        logging.getLogger().setLevel(logging.ERROR)
        # Specifically silence noisy libraries even if they don't respect root sometimes
        logging.getLogger("httpx").setLevel(logging.ERROR)
        logging.getLogger("httpcore").setLevel(logging.ERROR)
        logging.getLogger("openai").setLevel(logging.ERROR)

    abs_repo_path = Path(REPO_PATH).resolve()
    if args.verbose:
        print(f"Target Repo: {abs_repo_path}")
    
    # Ensure clean state before starting
    cleanup_repo(str(abs_repo_path))
    
    commits = get_commits(str(abs_repo_path), PREV_TAG, VERSION_TAG)
    if args.verbose:
        print(f"Found {len(commits)} commits to analyze between {PREV_TAG} and {VERSION_TAG}.")
    
    if not commits:
        print("No commits found.")
        return
        
    predictions = []
    timings = [] # List of {commit, pre, static, dynamic}
    stats = {
        "total_commits": len(commits),
        "failed_requests": 0,
        "failed_commits": 0,
        "empty_dynamic": 0,
        "predictions": {"malware": 0, "benign": 0, "unknown": 0}
    }
    
    # Shared resources and locks
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    repo_lock = threading.Lock() # Lock for git operations and dynamic analysis on cache miss
    stats_lock = threading.Lock() # Lock for updating stats
    file_lock = threading.Lock() # Lock for writing partial results
    
    # Load Cache
    dynamic_cache = {}
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                dynamic_cache = json.load(f)
            if args.verbose:
                print(f"Loaded {len(dynamic_cache)} cached dynamic reports.")
        except Exception as e:
            print(f"Warning: Failed to load cache file: {e}")
    
    # Repo instance: Repository class reads git. If it just reads, it might be fine, but git commands strictly might need lock if they change CWD (which they shouldn't with -C)
    # However, cleanup_repo definitely needs exclusive access.
    
    def process_commit(commit_idx, commit_hash):
        try:
            # Thread-local result containers
            local_timings = {}
            local_prediction = None
            local_commit_timings = {'pre_analysis': 0.0, 'static_analysis': 0.0}
            
            if args.verbose:
                 # Just print simply to avoid messing up tqdm
                 pass 

            static_res = {}
            dynamic_res = {}
            analysis_failed = False
            
            # STATIC ANALYSIS
            # Instantiate per thread/task to avoid shared state issues (self.issues)
            local_static_analyzer = StaticAnalyzer()
            # We can use a shared Repository instance if it's stateless, but 'Repository' class might not be.
            # Let's instantiate it locally to be safe or use the shared one if we trust it.
            # 'Repository' seems to just run git commands.
            # BUT, we need to be careful about current working directory? No, -C handles it.
            local_repo = Repository(str(abs_repo_path))
            
            try:
                # print(f"  [{commit_hash[:8]}] Running Static Analysis...")
                static_start = time.time()
                static_output = local_static_analyzer.analyze_commits(local_repo, [commit_hash])
                
                commit_timings = static_output.get('timings', {}).get(commit_hash, {'pre_analysis': 0.0, 'static_analysis': time.time() - static_start})
                local_commit_timings = commit_timings
                
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
            except Exception as e:
                print(f"  [{commit_hash[:8]}] Static analysis failed: {e}")
                with stats_lock:
                    stats["failed_requests"] += 1
                analysis_failed = True

            # DYNAMIC ANALYSIS
            dynamic_duration = 0.0
            try:
                # Check cache first (using short hash)
                short_commit = commit_hash[:8]
                is_cached = False
                
                # Check cache (read-only, no lock needed if dict is not modified, which it isn't here)
                if short_commit in dynamic_cache:
                    # print(f"  [{commit_hash[:8]}] Using cached dynamic report")
                    dynamic_res = dynamic_cache[short_commit]
                    dynamic_duration = 0.0
                    is_cached = True
                
                if not is_cached:
                    # Cache Miss - Need to run actual dynamic analysis
                    # This involves git operations (checkout) so we MUST lock the repo.
                    with repo_lock:
                        # Ensure clean state
                        cleanup_repo(str(abs_repo_path))
                        
                        # print(f"  [{commit_hash[:8]}] Running Dynamic Analysis (Cache Miss)...")
                        dynamic_start = time.time()
                        # Instantiate inside lock just in case
                        local_dynamic_analyzer = DynamicAnalyzer()
                        report_path = local_dynamic_analyzer.analyze(str(abs_repo_path), commit_hash)
                        dynamic_duration = time.time() - dynamic_start
                        
                        if report_path:
                            with open(report_path, 'r') as f:
                                dynamic_res = json.load(f)
                        
                        # Cleanup after
                        cleanup_repo(str(abs_repo_path))

                # Process results
                if dynamic_res:
                    if dynamic_res.get('status') == 'finished' and isinstance(dynamic_res.get('result'), list) and not dynamic_res.get('result'):
                         with stats_lock:
                            stats["empty_dynamic"] += 1
                else:
                    with stats_lock:
                        stats["empty_dynamic"] += 1
                    dynamic_res = {"error": "No report generated"}

            except Exception as e:
                print(f"  [{commit_hash[:8]}] Dynamic analysis failed: {e}")
                with stats_lock:
                    stats["failed_requests"] += 1
                analysis_failed = True
                
            if analysis_failed:
                with stats_lock:
                    stats["failed_commits"] += 1

            # VERIFICATION
            verification_start = time.time()
            verification_duration = 0.0
            try:
                prediction, explanation = simple_verification(commit_hash, static_res, dynamic_res)
                verification_duration = time.time() - verification_start
                
                label = "unknown"
                if "malware" in prediction:
                    label = "malware"
                elif "benign" in prediction:
                    label = "benign"
                
                with stats_lock:
                    stats["predictions"][label] = stats["predictions"].get(label, 0) + 1
                
                local_prediction = {
                    "hash": commit_hash,
                    "sample_folder": "mongoose",
                    "predict": label,
                    "explanation": explanation
                }
                
                # print(f"  [{commit_hash[:8]}] Result: {label.upper()}")
                
            except Exception as e:
                print(f"  [{commit_hash[:8]}] Verification failed: {e}")
                verification_duration = time.time() - verification_start
                with stats_lock:
                    stats["failed_requests"] += 1

            # Prepare timing entry
            timing_entry = {
                "commit": commit_hash,
                "pre_analysis_time": local_commit_timings['pre_analysis'],
                "static_analysis_time": local_commit_timings['static_analysis'],
                "dynamic_analysis_time": dynamic_duration,
                "verification_time": verification_duration
            }
            
            return timing_entry, local_prediction

        except Exception as e:
            print(f"Critical error processing commit {commit_hash}: {e}")
            return None, None

    # Run Concurrent Execution
    MAX_WORKERS = 8
    print(f"Starting analysis with {MAX_WORKERS} threads...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all tasks
        future_to_commit = {executor.submit(process_commit, i, commit): commit for i, commit in enumerate(commits)}
        
        # Iteration with progress bar
        if args.verbose:
            iterator = as_completed(future_to_commit)
        else:
            iterator = tqdm(as_completed(future_to_commit), total=len(commits), desc="Analyzing Commits", unit="commit")
            
        for future in iterator:
            commit = future_to_commit[future]
            try:
                t_entry, prediction = future.result()
                
                if t_entry and prediction:
                    with file_lock:
                        timings.append(t_entry)
                        predictions.append(prediction)
                        
                        # Incremental saves
                        with open('predicted_time.json', 'w') as f:
                            json.dump(timings, f, indent=2)
                        with open(PREDICTED_COMMITS_FILE, 'w') as f:
                            json.dump(predictions, f, indent=2)
                            
            except Exception as e:
                print(f"Generated exception for commit {commit}: {e}")

    # Recalculate empty dynamic count from actual report files
    actual_empty_dynamic = recalculate_empty_dynamic(len(commits))
    
    # Calculate accuracy and timing metrics
    accuracy_metrics = calculate_accuracy_metrics(predictions)
    timing_stats = calculate_timing_stats(timings)
    
    # Check if all commits used cache (total dynamic time is 0 and we have commmits)
    all_cached = False
    if timings and timing_stats and timing_stats['dynamic_analysis_time']['max'] == 0:
         all_cached = True
    

    # Load truth labels for report
    truth_map = {}
    truth_file = 'truth_commits.json'
    if not os.path.exists(truth_file):
        truth_file = 'truth_subset_commits.json'
    
    if os.path.exists(truth_file):
        try:
            with open(truth_file, 'r') as f:
                truth_data = json.load(f)
            truth_map = {item['hash']: item['label'] for item in truth_data}
        except Exception as e:
            print(f"Warning: Could not load truth file for report labels: {e}")

    # Write Report
    with open(REPORT_FILE, 'w') as f:
        f.write("# Stress Test Report\n\n")
        f.write(f"**Target:** {REPO_PATH}\n")
        f.write(f"**Range:** {PREV_TAG} -> {VERSION_TAG}\n")
        f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Statistics\n")
        f.write(f"- Total Commits Analyzed: {stats['total_commits']}\n")
        f.write(f"- Failed Requests: {stats['failed_requests']}\n")
        f.write(f"- Failed Commits: {stats['failed_commits']}\n")
        f.write(f"- Empty Dynamic: {actual_empty_dynamic}\n")
        
        f.write("\n## Predictions\n")
        for k, v in stats["predictions"].items():
            f.write(f"- {k}: {v}\n")
            
        f.write("\n## Accuracy Metrics\n")
        if accuracy_metrics:
            am = accuracy_metrics
            f.write(f"- Accuracy: {am['accuracy']:.2%}\n")
            f.write(f"- Precision: {am['precision']:.2%}\n")
            f.write(f"- Recall: {am['recall']:.2%}\n")
            f.write(f"- F1 Score: {am['f1']:.2%}\n")
            f.write(f"\n*Evaluated against {am['total_eval']} commits (TP:{am['tp']} FP:{am['fp']} TN:{am['tn']} FN:{am['fn']}). Missing/Unknown: {am['missing']}/{am['unknown']}*\n")
        else:
            f.write("Could not calculate accuracy (Missing truth file or no matches).\n")

        f.write("\n## Timing Statistics (Seconds)\n")
        if timing_stats:
            f.write("| Metric | Max | Min | Average | Total |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- |\n")
            for k, v in timing_stats.items():
                if k != 'overall_wall_clock':
                    name = k.replace('_', ' ').title()
                    
                    if k == 'dynamic_analysis_time' and all_cached:
                         f.write(f"| {name} | cached | cached | cached | cached |\n")
                    else:
                         f.write(f"| {name} | {v['max']:.4f}s | {v['min']:.4f}s | {v['avg']:.4f}s | {v['total']:.2f}s |\n")
            f.write(f"\n**Overall Wall Clock Time:** {timing_stats['overall_wall_clock']/60:.2f} minutes ({timing_stats['overall_wall_clock']:.2f} seconds)\n")
        else:
            f.write("No timing data available.\n")
        
        f.write("\n## Detailed Commits\n")
        # Ensure predictions are sorted by processing order or hash for consistency
        # Since multithreading mixes order, let sort by hash for deterministic report
        predictions.sort(key=lambda x: x['hash'])
        
        for p in predictions:
            commit_hash = p['hash']
            f.write(f"### Commit {commit_hash[:8]}: {p['predict'].capitalize()}\n")
            if p.get('explanation'):
                f.write(f"{p['explanation']}\n")
            else:
                f.write("No detailed explanation available.\n")
            
            # Add Truth label
            if commit_hash in truth_map:
                t_label = truth_map[commit_hash]
                # Capitalize: malware -> Malware, benign -> Benign
                f.write(f"**Truth label:** {t_label.capitalize()}\n\n")
            else:
                f.write("**Truth label:** Unknown\n\n")
    
    print(f"Saved report to {REPORT_FILE}")

if __name__ == "__main__":
    main()
