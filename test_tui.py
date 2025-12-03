#!/usr/bin/env python3
"""
Simple test script to verify TUI module functionality
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")
    
    try:
        from tui import FZFInterface, HistoryManager, GitHelper, CommitDetectionTUI
        print("✅ TUI module imports successful")
    except ImportError as e:
        print(f"❌ Failed to import TUI module: {e}")
        return False
    
    try:
        from main import main, run_tui_mode, run_analysis, run_static_analysis, run_dynamic_analysis
        print("✅ Main module imports successful")
    except ImportError as e:
        print(f"❌ Failed to import main module: {e}")
        return False
    
    return True


def test_history_manager():
    """Test history manager functionality"""
    print("\nTesting HistoryManager...")
    
    from tui import HistoryManager
    
    history = HistoryManager()
    
    # Test loading (should not crash even if file doesn't exist)
    entries = history.load_history()
    print(f"✅ Loaded {len(entries)} history entries")
    
    return True


def test_git_helper():
    """Test git helper functions"""
    print("\nTesting GitHelper...")
    
    from tui import GitHelper
    
    git = GitHelper()
    
    # Test checking if current directory is a git repo
    current_dir = Path.cwd()
    is_repo = git.is_git_repo(current_dir)
    print(f"✅ Current directory is git repo: {is_repo}")
    
    # If it is a repo, test getting remote URL
    if is_repo:
        remote_url = git.get_remote_url(current_dir)
        print(f"✅ Remote URL: {remote_url or 'None'}")
        
        repo_name = git.get_repo_name(current_dir)
        print(f"✅ Repo name: {repo_name or 'None'}")
    
    return True


def test_fzf_availability():
    """Test if fzf is available"""
    print("\nTesting fzf availability...")
    
    import shutil
    
    if shutil.which("fzf"):
        print("✅ fzf is installed and available")
        return True
    else:
        print("⚠️  fzf is not installed (required for interactive mode)")
        print("   Install with: sudo apt install fzf  (Ubuntu/Debian)")
        print("              or: brew install fzf       (macOS)")
        return False


def main():
    """Run all tests"""
    print("="*60)
    print("NPM Commit Detection - TUI Module Tests")
    print("="*60)
    
    results = []
    
    results.append(("Imports", test_imports()))
    results.append(("History Manager", test_history_manager()))
    results.append(("Git Helper", test_git_helper()))
    results.append(("fzf Availability", test_fzf_availability()))
    
    print("\n" + "="*60)
    print("Test Results Summary")
    print("="*60)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    all_passed = all(passed for _, passed in results)
    
    print("\n" + "="*60)
    if all_passed:
        print("✅ All tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed (see above)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
