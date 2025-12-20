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
import logging
from tqdm import tqdm
import statistics
import logging
load_dotenv()
logger = logging.getLogger(__name__)
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
        logger.error(f"Error checking accuracy: {e}")
        return {}

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
        logger.error(f"Error getting commits: {e}")
        return []

def cleanup_repo(repo_path):
    """Clean up git repo state to avoid 'resolve index' errors"""
    try:
        # Reset to HEAD to clear any staging area mess from failed merges/checkouts
        subprocess.run(["git", "-C", repo_path, "reset", "--hard"], check=False, capture_output=True)
        subprocess.run(["git", "-C", repo_path, "clean", "-fd"], check=False, capture_output=True)
    except Exception as e:
        logger.warning(f"Warning: Failed to cleanup repo: {e}")

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
                "line": line number (int/string),
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
            line_num = f.get("line", "?")
            code = f.get("code", "").strip()
            reason = f.get("reason", "")
            
            lines.append(f"**At line {line_num} file {file_path}**:")
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
        logger.error(f"LLM invocation failed: {e}")
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
        logger.error(f"  Advanced verification failed: {e}")
        # Fallback
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

    
    # Reconfigure logging level based on args
    if not args.verbose:
        logging.getLogger().setLevel(logging.ERROR)
        
    # Silence noisy libraries
    logging.getLogger("httpx").setLevel(logging.ERROR)
    logging.getLogger("httpcore").setLevel(logging.ERROR)
    logging.getLogger("openai").setLevel(logging.ERROR)

    abs_repo_path = Path(REPO_PATH).resolve()
    logger.info(f"Target Repo: {abs_repo_path}")
    
    # Ensure clean state before starting
    cleanup_repo(str(abs_repo_path))
    
    commits = get_commits(str(abs_repo_path), PREV_TAG, VERSION_TAG)
    if args.verbose:
        logger.info(f"Found {len(commits)} commits to analyze between {PREV_TAG} and {VERSION_TAG}.")
    
    if not commits:
        logger.error("No commits found.")
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
    
    repo = Repository(str(abs_repo_path))
    static_analyzer = StaticAnalyzer()
    dynamic_analyzer = DynamicAnalyzer()
    
    dynamic_analyzer = DynamicAnalyzer()
    
    # Setup iterator
    if args.verbose:
        commit_iter = enumerate(commits)
    else:
        commit_iter = enumerate(tqdm(commits, desc="Analyzing Commits", unit="commit"))

    for i, commit in commit_iter:
        if args.verbose:
            logger.info(f"[{i+1}/{len(commits)}] Processing commit {commit[:8]}...")
            
        # Ensure clean state before each dynamic analysis checkout attempt
        cleanup_repo(str(abs_repo_path))
        
        static_res = {}
        dynamic_res = {}
        static_output = {}  # Full output for advanced verification
        report_path = None  # Dynamic report path for advanced verification
        analysis_failed = False
        
        # STATIC ANALYSIS
        try:
            logger.info("Running Static Analysis...")
            static_start = time.time()
            static_output = static_analyzer.analyze_commits(repo, [commit])
            
            # Extract timings
            commit_timings = static_output.get('timings', {}).get(commit, {'pre_analysis': 0.0, 'static_analysis': time.time() - static_start})
            
            issues_list = []
            if 'all_issues' in static_output:
                for issue in static_output['all_issues']:
                    issues_list.append((str(issue.category), str(issue.severity)))
                    
            logger.info(f"Static analysis complete. Issues: {len(issues_list)}")
            
            static_res = {
                'total_issues': static_output.get('total_issues', 0),
                'issues': issues_list # Simplified for now as full object passed to verify
            }
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            stats["failed_requests"] += 1
            analysis_failed = True
            commit_timings = {'pre_analysis': 0.0, 'static_analysis': 0.0}

        # DYNAMIC ANALYSIS
        try:
            logger.info("Running Dynamic Analysis...")
            dynamic_start = time.time()
            report_path = dynamic_analyzer.analyze(str(abs_repo_path), commit)
            dynamic_duration = time.time() - dynamic_start
            
            if report_path:
                with open(report_path, 'r') as f:
                    dynamic_res = json.load(f)
                
                # Check for empty result specifically
                if dynamic_res.get('status') == 'finished' and isinstance(dynamic_res.get('result'), list) and not dynamic_res.get('result'):
                    logger.info("Dynamic analysis finished with empty result (no findings).")
                    stats["empty_dynamic"] += 1
            else:
                logger.warning("Dynamic analysis returned no report.")
                stats["empty_dynamic"] += 1
                dynamic_res = {"error": "No report generated"}
        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            stats["failed_requests"] += 1
            analysis_failed = True
            dynamic_duration = 0.0

        if analysis_failed:
            stats["failed_commits"] += 1
        
        # Verification
        logger.info("Running Simple Verification...")
        verification_start = time.time()
        verification_duration = 0.0
        try:
            # Use simple verification as requested (more robust/consistent for USER)
            prediction, explanation = simple_verification(commit, static_res, dynamic_res)
            verification_duration = time.time() - verification_start
            
            label = "unknown"
            if "malware" in prediction:
                label = "malware"
            elif "benign" in prediction:
                label = "benign"
            
            stats["predictions"][label] = stats["predictions"].get(label, 0) + 1
            
            predictions.append({
                "hash": commit,
                "sample_folder": "mongoose",
                "predict": label,
                "explanation": explanation
            })

            logger.info(f"Verification Result: {label.upper()}")
            
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            verification_duration = time.time() - verification_start
            stats["failed_requests"] += 1
        
        # Record Timing (now includes verification time)
        timing_entry = {
            "commit": commit,
            "pre_analysis_time": commit_timings['pre_analysis'],
            "static_analysis_time": commit_timings['static_analysis'],
            "dynamic_analysis_time": dynamic_duration,
            "verification_time": verification_duration
        }
        timings.append(timing_entry)
        
        # Save incremental timings
        with open('predicted_time.json', 'w') as f:
            json.dump(timings, f, indent=2)
            
        # Incremental save predictions
        with open(PREDICTED_COMMITS_FILE, 'w') as f:
            json.dump(predictions, f, indent=2)

    # Recalculate empty dynamic count from actual report files
    actual_empty_dynamic = recalculate_empty_dynamic(len(commits))
    
    # Calculate accuracy and timing metrics
    accuracy_metrics = calculate_accuracy_metrics(predictions)
    timing_stats = calculate_timing_stats(timings)
    
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
                    f.write(f"| {name} | {v['max']:.4f}s | {v['min']:.4f}s | {v['avg']:.4f}s | {v['total']:.2f}s |\n")
            f.write(f"\n**Overall Wall Clock Time:** {timing_stats['overall_wall_clock']/60:.2f} minutes ({timing_stats['overall_wall_clock']:.2f} seconds)\n")
        else:
            f.write("No timing data available.\n")
        
        f.write("\n## Detailed Commits\n")
        for p in predictions:
            f.write(f"### Commit {p['hash'][:8]}: {p['predict'].capitalize()}\n")
            if p.get('explanation'):
                f.write(f"{p['explanation']}\n\n")
            else:
                f.write("No detailed explanation available.\n\n")
    
    logger.info(f"Saved report to {REPORT_FILE}")

if __name__ == "__main__":
    main()
