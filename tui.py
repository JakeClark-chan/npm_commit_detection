#!/usr/bin/env python3
"""
TUI Module for NPM Commit Detection
Interactive interface using fzf for repository selection and analysis configuration
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from datetime import datetime


class FZFInterface:
    """Wrapper for fzf command-line fuzzy finder"""
    
    def __init__(self):
        if not shutil.which("fzf"):
            print("❌ Error: fzf is not installed on your system.")
            print("   Install with: sudo apt install fzf  (Ubuntu/Debian)")
            print("              or: brew install fzf       (macOS)")
            sys.exit(1)
    
    def run(self, items: List[str] = None, title: str = "Select an option", 
            prompt: str = "> ", print_query: bool = False, 
            multi: bool = False) -> Optional[str]:
        """
        Run fzf with given items
        
        Args:
            items: List of items to display
            title: Header title
            prompt: Prompt string
            print_query: Allow custom text input
            multi: Allow multiple selections
            
        Returns:
            Selected item(s) or None if cancelled
        """
        cmd = [
            "fzf",
            "--reverse",
            f"--header={title}",
            f"--prompt={prompt}",
            "--cycle",
            "--height=80%"
        ]
        
        if print_query:
            cmd.append("--print-query")
        
        if multi:
            cmd.append("--multi")
        
        input_str = "\n".join(str(x) for x in items) if items else ""
        
        try:
            result = subprocess.run(
                cmd,
                input=input_str,
                stdout=subprocess.PIPE,
                stderr=None,
                text=True
            )
            
            selection = result.stdout.strip()
            
            if result.returncode == 130:  # User pressed ESC
                return None
            
            return selection if selection else None
            
        except Exception as e:
            print(f"❌ Error running fzf: {e}")
            return None


class HistoryManager:
    """Manage recently used repositories"""
    
    def __init__(self):
        self.history_file = Path.home() / ".npm_commit_detection_history.json"
        self.max_entries = 20
    
    def load_history(self) -> List[Dict]:
        """Load history from file"""
        if not self.history_file.exists():
            return []
        
        try:
            with open(self.history_file, 'r') as f:
                return json.load(f)
        except Exception:
            return []
    
    def save_history(self, history: List[Dict]):
        """Save history to file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(history[:self.max_entries], f, indent=2)
        except Exception as e:
            print(f"⚠️  Warning: Could not save history: {e}")
    
    def add_entry(self, repo_path: str, repo_name: str = None, remote_url: str = None):
        """Add entry to history"""
        history = self.load_history()
        
        # Remove duplicate if exists
        history = [h for h in history if h.get('repo_path') != repo_path]
        
        # Add new entry at the beginning
        entry = {
            'repo_path': repo_path,
            'repo_name': repo_name,
            'remote_url': remote_url,
            'timestamp': datetime.now().isoformat()
        }
        history.insert(0, entry)
        
        self.save_history(history)


class GitHelper:
    """Helper functions for Git operations"""
    
    @staticmethod
    def is_git_repo(path: Path) -> bool:
        """Check if path is a git repository"""
        return (path / ".git").exists()
    
    @staticmethod
    def get_repo_name(repo_path: Path) -> Optional[str]:
        """Get repository name from package.json"""
        package_json = repo_path / "package.json"
        if package_json.exists():
            try:
                with open(package_json, 'r') as f:
                    data = json.load(f)
                    return data.get('name')
            except Exception:
                pass
        return None
    
    @staticmethod
    def get_remote_url(repo_path: Path) -> Optional[str]:
        """Get git remote URL"""
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except Exception:
            return None
    
    @staticmethod
    def get_tags_sorted_by_date(repo_path: Path) -> List[Tuple[str, str]]:
        """
        Get all tags sorted by date (newest first)
        Returns list of (tag_name, date) tuples
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "tag", "-l", "--sort=-creatordate", 
                 "--format=%(refname:short)|%(creatordate:short)"],
                capture_output=True,
                text=True,
                check=True
            )
            
            tags = []
            for line in result.stdout.strip().split('\n'):
                if '|' in line:
                    tag, date = line.split('|', 1)
                    tags.append((tag, date))
            
            return tags
        except Exception:
            return []
    
    @staticmethod
    def get_commits_between_tags(repo_path: Path, start_tag: str, end_tag: str) -> List[Tuple[str, str, str]]:
        """
        Get commits between two tags
        Returns list of (hash, date, subject) tuples, sorted by date (newest first)
        """
        try:
            # Get commit range
            if start_tag:
                commit_range = f"{start_tag}..{end_tag}"
            else:
                commit_range = end_tag
            
            result = subprocess.run(
                ["git", "-C", str(repo_path), "log", commit_range, 
                 "--pretty=format:%H|%cs|%s", "--reverse"],
                capture_output=True,
                text=True,
                check=True
            )
            
            commits = []
            for line in result.stdout.strip().split('\n'):
                if line and '|' in line:
                    parts = line.split('|', 2)
                    if len(parts) == 3:
                        commits.append((parts[0], parts[1], parts[2]))
            
            # Return in reverse order (newest first)
            return list(reversed(commits))
        except Exception:
            return []
    
    @staticmethod
    def get_all_commits(repo_path: Path, limit: int = 100) -> List[Tuple[str, str, str]]:
        """
        Get all commits from repository
        Returns list of (hash, date, subject) tuples, sorted by date (newest first)
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "log", 
                 f"-{limit}", "--pretty=format:%H|%cs|%s"],
                capture_output=True,
                text=True,
                check=True
            )
            
            commits = []
            for line in result.stdout.strip().split('\n'):
                if line and '|' in line:
                    parts = line.split('|', 2)
                    if len(parts) == 3:
                        commits.append((parts[0], parts[1], parts[2]))
            
            return commits
        except Exception:
            return []
    
    @staticmethod
    def clone_repo(url: str, dest_path: Path) -> bool:
        """Clone repository from URL"""
        try:
            print(f"📥 Cloning repository from {url}...")
            subprocess.run(
                ["git", "clone", url, str(dest_path)],
                check=True,
                capture_output=True
            )
            print(f"✅ Repository cloned to {dest_path}")
            return True
        except Exception as e:
            print(f"❌ Failed to clone repository: {e}")
            return False
    
    @staticmethod
    def find_git_repos(root_path: Path, max_depth: int = 3) -> List[Path]:
        """
        Recursively find all git repositories under root_path
        """
        repos = []
        
        def scan_dir(path: Path, current_depth: int):
            if current_depth > max_depth:
                return
            
            try:
                # Check if current directory is a git repo
                if GitHelper.is_git_repo(path):
                    repos.append(path)
                    return  # Don't scan subdirectories of a git repo
                
                # Scan subdirectories
                for item in path.iterdir():
                    if item.is_dir() and not item.name.startswith('.'):
                        scan_dir(item, current_depth + 1)
            except PermissionError:
                pass
        
        scan_dir(root_path, 0)
        return repos


class CommitDetectionTUI:
    """Main TUI class for commit detection workflow"""
    
    def __init__(self):
        self.fzf = FZFInterface()
        self.history = HistoryManager()
        self.git = GitHelper()
        
        # State
        self.repo_path: Optional[Path] = None
        self.repo_name: Optional[str] = None
        self.remote_url: Optional[str] = None
        self.start_tag: Optional[str] = None
        self.end_tag: Optional[str] = None
        self.commit_hash: Optional[str] = None
        self.skip_static: bool = False
        self.skip_dynamic: bool = False
    
    def phase1_choose_repo(self) -> bool:
        """Phase 1: Choose repository source"""
        options = [
            "1. Select from local folder",
            "2. Clone from remote URL",
            "3. Choose from recent history",
            "4. Exit"
        ]
        
        selection = self.fzf.run(
            items=options,
            title="PHASE 1: Repository Selection\nChoose how to select repository",
            prompt="Select> "
        )
        
        if not selection:
            return False
        
        mode = selection.split(".")[0]
        
        if mode == "1":
            return self._select_from_folder()
        elif mode == "2":
            return self._clone_from_url()
        elif mode == "3":
            return self._select_from_history()
        else:
            return False
    
    def _select_from_folder(self) -> bool:
        """Select repository from local folder"""
        current_dir = Path.cwd()
        
        while True:
            # Scan for git repositories
            print(f"🔍 Scanning for Git repositories in {current_dir}...")
            repos = self.git.find_git_repos(current_dir)
            
            if not repos:
                print("❌ No Git repositories found in current directory")
                retry = self.fzf.run(
                    items=["1. Try again", "2. Go back"],
                    title="No repositories found",
                    prompt="Action> "
                )
                if not retry or "2" in retry:
                    return False
                continue
            
            # Format repository list
            repo_items = ["<< GO UP ONE DIRECTORY", "<< BACK TO MAIN MENU"]
            for repo in repos:
                repo_name = self.git.get_repo_name(repo)
                remote_url = self.git.get_remote_url(repo)
                
                display = str(repo.relative_to(current_dir) if repo != current_dir else ".")
                if repo_name:
                    display += f" - {repo_name}"
                if remote_url:
                    display += f" - {remote_url}"
                
                repo_items.append(display)
            
            selection = self.fzf.run(
                items=repo_items,
                title=f"Select repository from: {current_dir}",
                prompt="Repo> "
            )
            
            if not selection:
                return False
            
            if selection == "<< GO UP ONE DIRECTORY":
                current_dir = current_dir.parent
                continue
            elif selection == "<< BACK TO MAIN MENU":
                return False
            
            # Extract repo path from selection
            repo_rel_path = selection.split(" - ")[0]
            if repo_rel_path == ".":
                self.repo_path = current_dir
            else:
                self.repo_path = current_dir / repo_rel_path
            
            self.repo_name = self.git.get_repo_name(self.repo_path)
            self.remote_url = self.git.get_remote_url(self.repo_path)
            
            # Add to history
            self.history.add_entry(str(self.repo_path), self.repo_name, self.remote_url)
            
            return True
    
    def _clone_from_url(self) -> bool:
        """Clone repository from remote URL"""
        url = self.fzf.run(
            items=[],
            title="Enter Git repository URL",
            prompt="URL> ",
            print_query=True
        )
        
        if not url:
            return False
        
        # Extract URL (fzf with --print-query returns query on first line)
        url = url.split('\n')[0].strip()
        
        if not url:
            return False
        
        # Generate destination path in /tmp
        repo_name = url.rstrip('/').split('/')[-1].replace('.git', '')
        dest_path = Path("/tmp") / f"npm_commit_detection_{repo_name}_{int(datetime.now().timestamp())}"
        
        # Clone repository
        if not self.git.clone_repo(url, dest_path):
            return False
        
        self.repo_path = dest_path
        self.repo_name = self.git.get_repo_name(self.repo_path)
        self.remote_url = url
        
        # Add to history
        self.history.add_entry(str(self.repo_path), self.repo_name, self.remote_url)
        
        return True
    
    def _select_from_history(self) -> bool:
        """Select repository from recent history"""
        history = self.history.load_history()
        
        if not history:
            print("❌ No recent history found")
            input("Press Enter to continue...")
            return False
        
        # Format history items
        items = []
        for entry in history:
            repo_path = entry.get('repo_path', 'Unknown')
            repo_name = entry.get('repo_name', '')
            remote_url = entry.get('remote_url', '')
            timestamp = entry.get('timestamp', '')
            
            display = repo_path
            if repo_name:
                display += f" - {repo_name}"
            if remote_url:
                display += f" - {remote_url}"
            if timestamp:
                display += f" ({timestamp[:10]})"
            
            items.append(display)
        
        selection = self.fzf.run(
            items=items,
            title="Select from recent history",
            prompt="History> "
        )
        
        if not selection:
            return False
        
        # Find selected entry
        for entry in history:
            if entry.get('repo_path') in selection:
                repo_path = Path(entry.get('repo_path'))
                
                # Check if repo still exists
                if not repo_path.exists():
                    print(f"❌ Repository no longer exists: {repo_path}")
                    input("Press Enter to continue...")
                    return False
                
                self.repo_path = repo_path
                self.repo_name = entry.get('repo_name')
                self.remote_url = entry.get('remote_url')
                return True
        
        return False
    
    def phase2_choose_start_tag(self) -> bool:
        """Phase 2: Choose start tag (earlier point) for static analysis"""
        tags = self.git.get_tags_sorted_by_date(self.repo_path)
        
        if not tags:
            print("❌ No tags found in repository")
            self.skip_static = True
            self.skip_dynamic = True
            return False
        
        # Format tag list
        items = ["<< SKIP STATIC ANALYSIS"]
        for tag, date in tags:
            items.append(f"{tag} ({date})")
        
        selection = self.fzf.run(
            items=items,
            title="PHASE 2: Choose start point for static analysis",
            prompt="Start Tag> "
        )
        
        if not selection:
            return False
        
        if selection == "<< SKIP STATIC ANALYSIS":
            self.skip_static = True
            return True
        
        # Extract tag name
        self.start_tag = selection.split(" (")[0]
        return True
    
    def phase3_choose_end_tag(self) -> bool:
        """Phase 3: Choose end tag (later point) for static analysis"""
        if self.skip_static:
            return True
        
        tags = self.git.get_tags_sorted_by_date(self.repo_path)
        
        # Filter tags that are after start_tag (newer/later)
        filtered_tags = []
        for tag, date in tags:
            if tag == self.start_tag:
                break # Stop at start_tag
            filtered_tags.append((tag, date))
        
        # Format tag list
        items = []
        for tag, date in filtered_tags:
            items.append(f"{tag} ({date})")
        
        if not items:
            print("ℹ️  No later tags available, will analyze to latest")
            self.end_tag = None
            return True
        
        selection = self.fzf.run(
            items=items,
            title=f"PHASE 3: Choose end point (comparing from start tag: {self.start_tag})",
            prompt="End Tag> "
        )
        
        if not selection:
            # Allow skipping end tag selection (will use latest)
            self.end_tag = None
            return True
        
        # Extract tag name
        self.end_tag = selection.split(" (")[0]
        return True
    
    def phase4_choose_commit(self) -> bool:
        """Phase 4: Choose commit hash for dynamic analysis"""
        # If static analysis was skipped, get all commits from repository
        if self.skip_static:
            commits = self.git.get_all_commits(self.repo_path, limit=100)
            title = "PHASE 4: Choose commit for dynamic analysis (showing latest 100 commits)"
        else:
            # Get commits between selected tags
            if not self.end_tag:
                print("❌ No end tag selected, cannot choose commit")
                self.skip_dynamic = True
                return True
            
            commits = self.git.get_commits_between_tags(self.repo_path, self.start_tag, self.end_tag)
            
            if self.start_tag and self.end_tag:
                title = f"PHASE 4: Choose commit for dynamic analysis (from {self.start_tag} to {self.end_tag})"
            elif self.end_tag:
                title = f"PHASE 4: Choose commit for dynamic analysis (up to {self.end_tag})"
            else:
                title = "PHASE 4: Choose commit for dynamic analysis"
        
        if not commits:
            print("❌ No commits found")
            self.skip_dynamic = True
            return True
        
        # Format commit list
        items = ["<< SKIP DYNAMIC ANALYSIS"]
        for commit_hash, date, subject in commits:
            items.append(f"{commit_hash[:8]} ({date}) - {subject[:60]}")
        
        selection = self.fzf.run(
            items=items,
            title=title,
            prompt="Commit> "
        )
        
        if not selection:
            return False
        
        if selection == "<< SKIP DYNAMIC ANALYSIS":
            self.skip_dynamic = True
            return True
        
        # Extract commit hash
        self.commit_hash = selection.split(" ")[0]
        return True
    
    def phase5_confirm_and_execute(self) -> Dict:
        """Phase 5: Confirm selection and prepare execution"""
        # Build summary
        summary_lines = [
            "="*60,
            "CONFIGURATION SUMMARY",
            "="*60,
            f"Repository: {self.repo_path}",
        ]
        
        if self.repo_name:
            summary_lines.append(f"Package Name: {self.repo_name}")
        if self.remote_url:
            summary_lines.append(f"Remote URL: {self.remote_url}")
        
        summary_lines.append("")
        
        # Always show static analysis section
        summary_lines.append("STATIC ANALYSIS:")
        if not self.skip_static:
            summary_lines.append(f"  Start Tag: {self.start_tag}")
            summary_lines.append(f"  End Tag: {self.end_tag or 'None (to latest)'}")
        else:
            summary_lines.append("  Status: Skipped")
        
        summary_lines.append("")
        
        # Always show dynamic analysis section
        summary_lines.append("DYNAMIC ANALYSIS:")
        if not self.skip_dynamic:
            summary_lines.append(f"  Commit Hash: {self.commit_hash}")
        else:
            summary_lines.append("  Status: Skipped")
        
        summary_lines.append("")
        
        # Always show verification line at the end
        if not self.skip_static and not self.skip_dynamic:
            summary_lines.append("✅ Automatically verify both analyses after completion")
        
        summary_lines.append("="*60)
        
        # Show summary and get confirmation
        confirmation = self.fzf.run(
            items=["✅ CONFIRM AND START ANALYSIS", "❌ CANCEL"],
            title="PHASE 5: Confirm Configuration\n\n" + "\n".join(summary_lines),
            prompt="Action> "
        )
        
        if not confirmation or "CANCEL" in confirmation:
            return None
        
        # Return configuration
        return {
            'repo_path': str(self.repo_path),
            'repo_name': self.repo_name,
            'remote_url': self.remote_url,
            'end_tag': self.end_tag,
            'start_tag': self.start_tag,
            'commit_hash': self.commit_hash,
            'skip_static': self.skip_static,
            'skip_dynamic': self.skip_dynamic,
            'auto_verify': not self.skip_static and not self.skip_dynamic
        }
    
    def run(self) -> Optional[Dict]:
        """Run the complete TUI workflow"""
        print("\n" + "="*80)
        print("NPM COMMIT DETECTION - INTERACTIVE MODE")
        print("="*80 + "\n")
        
        # Phase 1: Choose repository
        if not self.phase1_choose_repo():
            print("❌ Repository selection cancelled")
            return None
        
        print(f"\n✅ Repository selected: {self.repo_path}\n")
        
        # Phase 2: Choose start tag
        if not self.phase2_choose_start_tag():
            print("❌ Start tag selection cancelled")
            return None
        
        if not self.skip_static:
            print(f"✅ Start tag selected: {self.start_tag}\n")
        else:
            print("⏭️  Static analysis skipped\n")
        
        # Phase 3: Choose end tag
        if not self.phase3_choose_end_tag():
            print("❌ End tag selection cancelled")
            return None
        
        if not self.skip_static:
            if self.end_tag:
                print(f"✅ End tag selected: {self.end_tag}\n")
            else:
                print("ℹ️  No end tag selected (analyzing to latest)\n")
        
        # Phase 4: Choose commit
        if not self.phase4_choose_commit():
            print("❌ Commit selection cancelled")
            return None
        
        if not self.skip_dynamic:
            print(f"✅ Commit selected: {self.commit_hash}\n")
        else:
            print("⏭️  Dynamic analysis skipped\n")
        
        # Phase 5: Confirm and execute
        config = self.phase5_confirm_and_execute()
        
        if not config:
            print("❌ Configuration cancelled")
            return None
        
        return config


def main():
    """Test the TUI"""
    tui = CommitDetectionTUI()
    config = tui.run()
    
    if config:
        print("\n" + "="*80)
        print("CONFIGURATION RESULT:")
        print("="*80)
        print(json.dumps(config, indent=2))
    else:
        print("\nOperation cancelled by user")


if __name__ == "__main__":
    main()
