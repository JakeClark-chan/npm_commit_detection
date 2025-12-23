#!/usr/bin/env python3
"""
Main entry point for NPM Commit Detection with LangGraph
Orchestrates pre-analysis, static analysis, dynamic analysis, and verification workflows
"""

import os
import sys
import json
import time
import threading
from pathlib import Path
from typing import Dict, TypedDict, Annotated, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from analyzers.pre_analysis import Repository, PreAnalyzer
from llm.static_analysis import StaticAnalyzer
from tools.dynamic_analysis import DynamicAnalyzer
from utils.tui import CommitDetectionTUI


# Load environment variables
load_dotenv()


class AnalysisState(TypedDict):
    """State for the analysis workflow"""
    # Input
    repo_path: str
    version_tag: str
    previous_tag: str
    commit_hash: str  # For dynamic analysis
    
    # Pre-analysis outputs
    pre_analysis_complete: bool
    pre_analysis_report: str
    commit_shas: list
    metadata_results: dict
    contributor_results: dict
    change_results: dict
    
    # Static analysis outputs
    static_analysis_complete: bool
    static_analysis_report: str
    static_analysis_output_file: str
    security_issues: list
    total_issues: int
    
    # Snyk analysis outputs
    snyk_analysis_complete: bool
    snyk_analysis_results: dict
    snyk_analysis_output_file: str
    
    # Dynamic analysis outputs
    dynamic_analysis_complete: bool
    dynamic_analysis_report: str
    dynamic_analysis_output_file: str
    
    # Verification outputs
    verification_complete: bool
    verification_report: str
    verification_output_file: str
    
    # Final report
    final_report: str
    output_file: str


def pre_analysis_node(state: AnalysisState) -> AnalysisState:
    """
    Pre-analysis node: Analyze metadata, contributors, and changes
    """
    print("\n" + "="*80)
    print("📊 PRE-ANALYSIS PHASE")
    print("="*80)
    
    repo_path = state['repo_path']
    version_tag = state['version_tag']
    previous_tag = state.get('previous_tag')
    
    # Initialize repository
    print(f"Initializing repository: {repo_path}")
    repo = Repository(repo_path)
    
    # Run pre-analysis
    print(f"Running pre-analysis for version: {version_tag}")
    if previous_tag:
        print(f"Comparing with previous version: {previous_tag}")
    
    analyzer = PreAnalyzer(repo)
    results = analyzer.analyze_version(version_tag, previous_tag)
    
    # Print report
    print("\n" + results['report_text'])
    
    # Update state
    state['pre_analysis_complete'] = True
    state['pre_analysis_report'] = results['report_text']
    state['commit_shas'] = results['commit_shas']
    state['metadata_results'] = results['metadata_results']
    state['contributor_results'] = results['contributor_results']
    state['change_results'] = results['change_results']
    
    return state


def static_analysis_node(state: AnalysisState) -> AnalysisState:
    """
    Static analysis node: Use LLM to detect vulnerabilities
    """
    print("\n" + "="*80)
    print("🔬 STATIC ANALYSIS PHASE")
    print("="*80)
    
    if not state.get('pre_analysis_complete'):
        raise RuntimeError("Pre-analysis must complete before static analysis")
    
    # Re-initialize repository for static analysis
    repo_path = state['repo_path']
    repository = Repository(repo_path)
    commit_shas = state['commit_shas']
    
    if not commit_shas:
        print("No commits to analyze. Skipping static analysis.")
        state['static_analysis_complete'] = True
        state['static_analysis_report'] = "No commits to analyze."
        state['security_issues'] = []
        state['total_issues'] = 0
        return state
    
    # Run static analysis with LLM (model config from .env)
    analyzer = StaticAnalyzer()  # Will read from .env
    results = analyzer.analyze_commits(repository, commit_shas)
    
    # Generate report
    report = analyzer.generate_report(results)
    print(report)
    
    # Update state
    state['static_analysis_complete'] = True
    state['static_analysis_report'] = report
    state['security_issues'] = [
        {
            'severity': issue.severity,
            'category': issue.category,
            'commit_sha': issue.commit_sha,
            'file_path': issue.file_path,
            'line_number': issue.line_number,
            'description': issue.description,
            'recommendation': issue.recommendation
        }
        for issue in results['all_issues']
    ]
    state['total_issues'] = results['total_issues']
    
    return state


def generate_final_report_node(state: AnalysisState) -> AnalysisState:
    """
    Generate final combined report
    """
    print("\n" + "="*80)
    print("📝 GENERATING FINAL REPORT")
    print("="*80)
    
    # Combine reports
    report_parts = [
        "="*80,
        "NPM COMMIT DETECTION - COMPREHENSIVE ANALYSIS REPORT",
        "="*80,
        f"\nRepository: {state['repo_path']}",
        f"Version: {state['version_tag']}",
        f"Previous Version: {state.get('previous_tag', 'N/A')}",
        f"Analysis Date: {datetime.now().isoformat()}",
        "\n" + "="*80,
        "PART 1: PRE-ANALYSIS",
        "="*80,
        state['pre_analysis_report'],
        "\n" + "="*80,
        "PART 2: STATIC ANALYSIS",
        "="*80,
        state['static_analysis_report'],
        "\n" + "="*80,
        "SUMMARY",
        "="*80,
        f"\nTotal commits analyzed: {len(state['commit_shas'])}",
        f"Total security issues found: {state['total_issues']}",
    ]
    
    if state['total_issues'] > 0:
        report_parts.append("\n⚠️  SECURITY ISSUES DETECTED - REVIEW REQUIRED")
        report_parts.append(f"\nCritical issues: {sum(1 for i in state['security_issues'] if i['severity'] == 'CRITICAL')}")
        report_parts.append(f"High severity issues: {sum(1 for i in state['security_issues'] if i['severity'] == 'HIGH')}")
    else:
        report_parts.append("\n✅ No security issues detected")
    
    report_parts.extend([
        "\n" + "="*80,
        "END OF REPORT",
        "="*80
    ])
    
    final_report = '\n'.join(report_parts)
    
    # Create reports directory if it doesn't exist
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    
    # Save to file
    version_safe = state['version_tag'].replace('/', '_')
    output_file = os.path.join(reports_dir, f"analysis_report_{version_safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    
    with open(output_file, 'w') as f:
        f.write(final_report)
    
    # Also save as JSON for LLM-friendly format
    json_file = output_file.replace('.txt', '.json')
    json_data = {
        'repository': state['repo_path'],
        'version': state['version_tag'],
        'previous_version': state.get('previous_tag'),
        'analysis_date': datetime.now().isoformat(),
        'total_commits': len(state['commit_shas']),
        'pre_analysis': {
            'metadata': state['metadata_results'],
            'contributors': state['contributor_results'],
            'changes': state['change_results']
        },
        'static_analysis': {
            'total_issues': state['total_issues'],
            'issues': state['security_issues']
        }
    }
    
    with open(json_file, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    print(f"\n✅ Report saved to: {output_file}")
    print(f"✅ JSON data saved to: {json_file}")
    
    state['final_report'] = final_report
    state['output_file'] = output_file
    
    return state


def create_workflow() -> StateGraph:
    """
    Create the LangGraph workflow
    """
    # Create workflow
    workflow = StateGraph(AnalysisState)
    
    # Add nodes
    workflow.add_node("pre_analysis", pre_analysis_node)
    workflow.add_node("static_analysis", static_analysis_node)
    workflow.add_node("generate_report", generate_final_report_node)
    
    # Define edges
    workflow.add_edge("pre_analysis", "static_analysis")
    workflow.add_edge("static_analysis", "generate_report")
    workflow.add_edge("generate_report", END)
    
    # Set entry point
    workflow.set_entry_point("pre_analysis")
    
    # Compile with checkpointer for memory
    memory = MemorySaver()
    app = workflow.compile(checkpointer=memory)
    
    return app


def run_tui_mode():
    """Run interactive TUI mode"""
    try:
        tui = CommitDetectionTUI()
        config = tui.run()
        
        if not config:
            print("\n❌ Configuration cancelled by user")
            sys.exit(0)
        
        return run_analysis(config)
    except Exception as e:
        print(f"❌ Error starting TUI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Main entry point"""
    # If no arguments provided, run interactive TUI mode
    if len(sys.argv) == 1:
        return run_tui_mode()
    
    # Command-line mode with arguments
    if len(sys.argv) < 3:
        print("Usage: python main.py <repo_path> <version_tag> [previous_tag] [--dynamic <commit_hash>] [--snyk] [--skip-dynamic]")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    version_tag = sys.argv[2]
    previous_tag = None
    commit_hash = None
    run_snyk = False
    skip_dynamic = False
    
    # Parse optional arguments
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--dynamic' and i + 1 < len(sys.argv):
            commit_hash = sys.argv[i + 1]
            i += 2
        elif arg == '--snyk':
            run_snyk = True
            i += 1
        elif arg == '--skip-dynamic':
            skip_dynamic = True
            i += 1
        else:
            if not previous_tag:
                previous_tag = arg
            i += 1
    
    # Verify repository exists
    if not Path(repo_path).exists():
        print(f"Error: Repository path does not exist: {repo_path}")
        sys.exit(1)
    
    # Check environment variables
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable not set")
        sys.exit(1)
    
    config = {
        'repo_path': repo_path,
        'end_tag': version_tag,
        'start_tag': previous_tag,
        'commit_hash': commit_hash,
        'run_snyk': run_snyk,
        'skip_static': False,
        'skip_dynamic': skip_dynamic or (commit_hash is None), # Skip dynamic if explicitly skipped or no hash
        'auto_verify': True # Always try to verify if we have data
    }
    
    return run_analysis(config)


def run_analysis(config: Dict) -> int:
    """
    Run analysis based on configuration
    """
    print("\n" + "="*80)
    print("NPM COMMIT DETECTION - COMPREHENSIVE ANALYSIS")
    print("="*80)
    print(f"Repository: {config['repo_path']}")
    if not config['skip_static']:
        print(f"Static Analysis: {config['start_tag'] or '(beginning)'} -> {config['end_tag']}")
    if not config['skip_dynamic']: 
        print(f"Dynamic Analysis: {config['commit_hash']}")
    if config['run_snyk']:
        print(f"Snyk Analysis: Enabled")
        
    print("="*80)
    
    static_output = None
    dynamic_output = None
    snyk_output = None
    
    analyzed_commits = []
    
    try:
        # Run analyses
        # Logic:
        # 1. Start Static Analysis (it finds commits).
        # 2. Start Dynamic Analysis (if specific hash). 
        # 3. If Snyk enabled:
        #    - If specific hash, run parallel.
        #    - If no specific hash (tag range), must wait for Static to identify commits, then run Snyk on them.
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            
            # Static
            if not config['skip_static']:
                futures[executor.submit(
                    run_static_analysis,
                    config['repo_path'],
                    config['end_tag'],
                    config['start_tag']
                )] = 'static'
            
            # Dynamic
            if not config['skip_dynamic'] and config['commit_hash']:
                futures[executor.submit(
                    run_dynamic_analysis,
                    config['repo_path'],
                    config['commit_hash']
                )] = 'dynamic'
            
            # Snyk (Single Commit)
            if config['run_snyk'] and config['commit_hash']:
                 futures[executor.submit(
                    run_snyk_analysis,
                    config['repo_path'],
                    config['commit_hash']
                )] = 'snyk'
            
            # Process results as they complete
            for future in as_completed(futures):
                analysis_type = futures[future]
                try:
                    result = future.result()
                    
                    if analysis_type == 'static':
                        # Static returns (report_path, commit_shas) now
                        static_output, analyzed_commits = result
                        print(f"\n✅ Static analysis completed: {static_output}")
                        print(f"   Analyzed {len(analyzed_commits)} commits")
                        
                    elif analysis_type == 'dynamic':
                        dynamic_output = result
                        print(f"\n✅ Dynamic analysis completed: {dynamic_output}")
                        
                    elif analysis_type == 'snyk':
                        snyk_output = result
                        print(f"\n✅ Snyk analysis completed: {snyk_output}")
                        
                except Exception as e:
                     print(f"\n❌ {analysis_type.capitalize()} analysis failed: {e}")
                     import traceback
                     traceback.print_exc()

        # Phase 2: Post-Static Snyk Analysis
        # If we need to run Snyk on a range of commits (from static analysis) and haven't run it yet
        if config['run_snyk'] and not config.get('commit_hash') and analyzed_commits:
            print(f"\n🔄 Running Snyk analysis on {len(analyzed_commits)} commits found by static analysis...")
            snyk_reports = []
            
            # We'll run Snyk only on the 'changes' - likely the commits found.
            # Running sequentially for now to avoid overloading or temp dir conflicts if not robust
            for sha in analyzed_commits:
                print(f"   🛡️ Scanning {sha[:8]}...")
                report_path = run_snyk_analysis(config['repo_path'], sha)
                if report_path:
                    snyk_reports.append(report_path)
            
            # For verification, we need to merge these reports or pass a list. 
            # verification.py expects a single JSON file path currently.
            # We should probably combine them into one 'snyk_analysis.json'.
            
            if snyk_reports:
                combined_snyk = {'all_issues': [], 'total_issues': 0}
                for rp in snyk_reports:
                    try:
                        with open(rp, 'r') as f:
                            data = json.load(f)
                            combined_issues = data.get('all_issues', []) 
                            # If snyk_analysis.py structure is normalized, it might be a list or dict.
                            # Based on run_snyk_analysis dump: json.dump(result, f)
                            # Let's check snyk_analysis.py return. It returns a Dict with 'all_issues'.
                            if isinstance(data, dict):
                                combined_snyk['all_issues'].extend(data.get('all_issues', []))
                    except:
                        pass
                
                combined_snyk['total_issues'] = len(combined_snyk['all_issues'])
                
                # Save combined
                reports_dir = Path("reports")
                combined_path = reports_dir / f"snyk_combined_{config['end_tag'].replace('/', '_')}.json"
                with open(combined_path, 'w') as f:
                    json.dump(combined_snyk, f, indent=2)
                
                snyk_output = str(combined_path)
                print(f"\n✅ Combined Snyk analysis completed: {snyk_output}")
        
        # Verify
        if config['auto_verify'] and (static_output or dynamic_output or snyk_output):
             print("\n" + "="*80)
             print("🔍 VERIFICATION PHASE")
             print("="*80)
             
             verification_output = run_verification(static_output, dynamic_output, snyk_output)
             
             if verification_output:
                 print(f"\n✅ Verification completed: {verification_output}\n")
             else:
                 print("\n⚠️  Verification completed with warnings\n")

        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
        return 130
    except Exception as e:
        print(f"\n\n❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1


def run_static_analysis(repo_path: str, end_tag: str, start_tag: Optional[str]) -> tuple[str, list]:
    """
    Run static analysis workflow
    
    Returns:
        Tuple of (Path to output JSON file, List of analyzed commit SHAs)
    """
    print("\n" + "="*80)
    print("📊 PRE-ANALYSIS PHASE")
    print("="*80)
    
    # Initialize repository
    repo = Repository(repo_path)
    
    # Run pre-analysis
    print(f"Running pre-analysis for version: {end_tag}")
    if start_tag:
        print(f"Comparing with previous version: {start_tag}")
    
    analyzer = PreAnalyzer(repo)
    results = analyzer.analyze_version(end_tag, start_tag)
    
    print("\n" + results['report_text'])
    
    commit_shas = results['commit_shas']
    
    
    # Run Static Analysis
    print("\n" + "="*80)
    print("🔬 STATIC ANALYSIS PHASE")
    print("="*80)
    
    if not commit_shas:
        print("No commits to analyze. Skipping static analysis.")
        # Save minimal report
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        version_safe = end_tag.replace('/', '_')
        output_file = reports_dir / f"analysis_report_{version_safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        json_data = {
            'repository': repo_path,
            'version': end_tag,
            'previous_version': start_tag,
            'analysis_date': datetime.now().isoformat(),
            'total_commits': 0,
            'pre_analysis': results,
            'static_analysis': {
                'total_issues': 0,
                'issues': []
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        return str(output_file), []

    # Run Deobfuscation Agent
    print("\n" + "="*80)
    print("🔓 DEOBFUSCATION PHASE")
    print("="*80)
    
    from llm.deobfuscator_agent import DeobfuscatorAgent
    deobfuscator = DeobfuscatorAgent()
    deobfuscated_data = deobfuscator.process_commits(repo, commit_shas)
    
    if deobfuscated_data:
        print(f"✅ Deobfuscation completed. Found obfuscated code in {len(deobfuscated_data)} commits.")
    else:
        print("✅ No obfuscated code detected requiring intervention.")
    
    static_analyzer = StaticAnalyzer()
    static_results = static_analyzer.analyze_commits(repo, commit_shas, deobfuscated_data)
    
    report = static_analyzer.generate_report(static_results)
    print(report)
    
    # Save report
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    version_safe = end_tag.replace('/', '_')
    output_file = reports_dir / f"analysis_report_{version_safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    json_data = {
        'repository': repo_path,
        'version': end_tag,
        'previous_version': start_tag,
        'analysis_date': datetime.now().isoformat(),
        'total_commits': len(commit_shas),
        'pre_analysis': {
            'metadata': results['metadata_results'],
            'contributors': results['contributor_results'],
            'changes': results['change_results']
        },
        'static_analysis': {
            'total_issues': static_results['total_issues'],
            'issues': [
                {
                    'severity': issue.severity,
                    'category': issue.category,
                    'commit_sha': issue.commit_sha,
                    'file_path': issue.file_path,
                    'line_number': issue.line_number,
                    'description': issue.description,
                    'recommendation': issue.recommendation
                }
                for issue in static_results['all_issues']
            ]
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    print(f"\n💾 Static analysis report saved: {output_file}")
    
    return str(output_file), commit_shas


def run_dynamic_analysis(repo_path: str, commit_hash: str) -> Optional[str]:
    """
    Run dynamic analysis
    
    Returns:
        Path to output JSON file or None if server unavailable
    """
    analyzer = DynamicAnalyzer()
    
    # Check if server is available, otherwise wait
    max_wait_time = 300  # 5 minutes
    wait_interval = 5
    elapsed = 0
    
    while not analyzer._check_server_availability():
        if elapsed == 0:
            print("\n⏳ Package Hunter server (localhost:3000) is not available")
            print("   Waiting for server to start...")
        
        if elapsed >= max_wait_time:
            print(f"\n❌ Timeout: Server did not start after {max_wait_time}s")
            print("   Please start the server manually:")
            print("   FALCO_TOKEN=<token> NODE_ENV=development DEBUG=pkgs* node src/server.js")
            return None
        
        time.sleep(wait_interval)
        elapsed += wait_interval
        
        if elapsed % 30 == 0:
            print(f"   Still waiting... ({elapsed}s elapsed)")
    
    if elapsed > 0:
        print(f"✅ Server is now available (waited {elapsed}s)")
    
    report_path = analyzer.analyze(repo_path, commit_hash)
    return report_path


def run_snyk_analysis(repo_path: str, commit_hash: str) -> Optional[str]:
    """
    Run Snyk SAST analysis on a specific commit
    """
    from tools.snyk_analysis import SnykAnalyzer
    from analyzers.pre_analysis import Repository
    
    print("\n" + "="*80)
    print("🛡️ SNYK ANALYSIS PHASE")
    print("="*80)
    
    repo = Repository(repo_path)
    snyk = SnykAnalyzer(repo_path)
    
    if not snyk.check_auth():
         print("⚠️  Snyk not authenticated. Skipping.")
         return None
         
    # Get files changed in this commit
    # We can use repo.get_file_changes(commit_hash) to find changed files
    # However that returns FileChange objects with filename
    changes = repo.get_file_changes(commit_hash)
    changed_files = [c.filename for c in changes]
    
    result = snyk.analyze_commit(commit_hash, changed_files)
    
    # Save report
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    output_file = reports_dir / f"snyk_report_{commit_hash[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
        
    print(f"\n💾 Snyk analysis report saved: {output_file}")
    
    return str(output_file)


def run_verification(static_report_path: Optional[str], dynamic_report_path: Optional[str], snyk_report_path: Optional[str] = None) -> Optional[str]:
    """
    Run verification with available reports
    """
    from llm.verification import verify_analysis
    
    if not static_report_path and not dynamic_report_path and not snyk_report_path:
        return None
        
    try:
        # If static/dynamic are None, we might need to handle them? 
        # verify_analysis currently expects static_analysis_json as 1st arg. 
        # If static is None, we might have an issue. 
        # But typically static is the base. If static is None, verify_analysis might fail loading the json.
        # Let's assume static is usually present, or we can't do much. 
        # But wait, if we only have Snyk + Dynamic?
        # verify_analysis tries to load static_analysis.json.
        # I should probably ensure static analysis JSON exists or mock it if strictly Snyk+Dynamic.
        # For now, let's assume Static is required by verification logic structure (it normalizes static first).
        
        if not static_report_path:
             print("⚠️  Static analysis report missing. Cannot run full verification.")
             return None
             
        result = verify_analysis(static_report_path, dynamic_report_path, ".", snyk_report_path)
        
        # Find the most recent verification report
        reports_dir = Path("reports")
        verification_files = sorted(reports_dir.glob("verification_report_*.md"))
        
        if verification_files:
            return str(verification_files[-1])
        return None
        
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def legacy_main():
    """Legacy main function for backward compatibility"""
    if len(sys.argv) < 3:
        print("Usage: python main.py <repo_path> <version_tag> [previous_tag]")
        print("Example: python main.py ../mongoose 8.19.1 8.19.0")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    version_tag = sys.argv[2]
    previous_tag = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Verify repository exists
    if not Path(repo_path).exists():
        print(f"Error: Repository path does not exist: {repo_path}")
        sys.exit(1)
    
    if not (Path(repo_path) / ".git").exists():
        print(f"Error: Not a git repository: {repo_path}")
        sys.exit(1)
    
    # Check environment variables
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable not set")
        sys.exit(1)
    
    # Enable LangSmith tracing if configured
    if os.getenv("LANGSMITH_API_KEY"):
        print("✅ LangSmith tracing enabled")
        print(f"   Project: {os.getenv('LANGSMITH_PROJECT', 'default')}")
    
    print("\n" + "="*80)
    print("NPM COMMIT DETECTION - COMPREHENSIVE ANALYSIS")
    print("="*80)
    print(f"Repository: {repo_path}")
    print(f"Version: {version_tag}")
    if previous_tag:
        print(f"Previous Version: {previous_tag}")
    print("="*80)
    
    # Create workflow
    app = create_workflow()
    
    # Prepare initial state
    initial_state = {
        'repo_path': repo_path,
        'version_tag': version_tag,
        'previous_tag': previous_tag,
        'commit_hash': None,
        'pre_analysis_complete': False,
        'static_analysis_complete': False,
        'dynamic_analysis_complete': False,
        'verification_complete': False,
        'commit_shas': [],
        'security_issues': [],
        'total_issues': 0
    }
    
    # Run workflow
    try:
        config = {"configurable": {"thread_id": "analysis_run_1"}}
        final_state = app.invoke(initial_state, config)
        
        print("\n" + "="*80)
        print("✅ ANALYSIS COMPLETE")
        print("="*80)
        print(f"Report: {final_state['output_file']}")
        
        # Return exit code based on findings
        if final_state['total_issues'] > 0:
            critical_count = sum(1 for i in final_state['security_issues'] if i['severity'] == 'CRITICAL')
            if critical_count > 0:
                print(f"\n⚠️  CRITICAL ISSUES FOUND: {critical_count}")
                sys.exit(2)  # Critical issues
            else:
                print(f"\n⚠️  SECURITY ISSUES FOUND: {final_state['total_issues']}")
                sys.exit(1)  # Non-critical issues
        else:
            print("\n✅ No security issues detected")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
