#!/usr/bin/env python3
"""
Pre-analysis module for detecting anomalous commits in npm repositories.
Based on "Anomalicious" paper (arXiv:2103.03846)

This module handles:
- Repository metadata analysis
- Contributor trust evaluation
- File change detection
- Sensitive file identification
"""

import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import re


@dataclass
class CommitMetadata:
    """Represents metadata of a single commit"""
    sha: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    date: datetime
    message: str
    parent_shas: List[str] = field(default_factory=list)
    
    def __str__(self):
        return f"Commit {self.sha[:8]} by {self.author_name} on {self.date}"


@dataclass
class FileChange:
    """Represents a file change in a commit"""
    filename: str
    status: str  # A=added, M=modified, D=deleted, R=renamed
    additions: int
    deletions: int
    is_sensitive: bool = False
    
    @property
    def total_changes(self) -> int:
        return self.additions + self.deletions


@dataclass
class ContributorProfile:
    """Profile and trust metrics for a contributor"""
    name: str
    email: str
    total_commits: int = 0
    first_commit_date: Optional[datetime] = None
    last_commit_date: Optional[datetime] = None
    files_touched: Set[str] = field(default_factory=set)
    commit_messages: List[str] = field(default_factory=list)
    
    @property
    def is_new_contributor(self) -> bool:
        """Check if contributor has very few commits"""
        return self.total_commits < 5
    
    @property
    def trust_score(self) -> float:
        """Calculate basic trust score (0-1)"""
        # Simple heuristic: more commits = more trust
        if self.total_commits == 0:
            return 0.0
        score = min(self.total_commits / 50.0, 1.0)
        return score


class Repository:
    """Represents a Git repository with analysis capabilities"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        if not (self.repo_path / ".git").exists():
            raise ValueError(f"Not a git repository: {repo_path}")
        
        self.name = self.repo_path.name
        self.contributors: Dict[str, ContributorProfile] = {}
        
    def _run_git(self, *args) -> str:
        """Execute git command and return output"""
        try:
            result = subprocess.run(
                ["git"] + list(args),
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Git command failed: {e.stderr}")
    
    def get_commit_metadata(self, commit_sha: str) -> CommitMetadata:
        """Extract metadata for a specific commit"""
        # Get commit info
        format_str = "%H%n%an%n%ae%n%cn%n%ce%n%ai%n%B%n---PARENTS---%n%P"
        output = self._run_git("show", "-s", f"--format={format_str}", commit_sha)
        
        lines = output.split('\n')
        sha = lines[0]
        author_name = lines[1]
        author_email = lines[2]
        committer_name = lines[3]
        committer_email = lines[4]
        date_str = lines[5]
        
        # Find message and parents
        parents_idx = lines.index("---PARENTS---")
        message = '\n'.join(lines[6:parents_idx])
        parents = lines[parents_idx + 1].split() if parents_idx + 1 < len(lines) else []
        
        return CommitMetadata(
            sha=sha,
            author_name=author_name,
            author_email=author_email,
            committer_name=committer_name,
            committer_email=committer_email,
            date=datetime.fromisoformat(date_str.replace(' +', '+')),
            message=message.strip(),
            parent_shas=parents
        )
    
    def get_file_changes(self, commit_sha: str) -> List[FileChange]:
        """Get list of file changes in a commit"""
        # Get numstat (additions/deletions per file)
        numstat = self._run_git("show", "--numstat", "--format=", commit_sha)
        
        changes = []
        for line in numstat.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            
            additions = int(parts[0]) if parts[0] != '-' else 0
            deletions = int(parts[1]) if parts[1] != '-' else 0
            filename = parts[2]
            
            # Get status (A/M/D/R)
            status_output = self._run_git("show", "--name-status", "--format=", commit_sha)
            status = 'M'  # default
            for status_line in status_output.split('\n'):
                if filename in status_line:
                    status = status_line.split('\t')[0][0]
                    break
            
            changes.append(FileChange(
                filename=filename,
                status=status,
                additions=additions,
                deletions=deletions
            ))
        
        return changes
    
    def get_commit_diff(self, commit_sha: str) -> str:
        """Get the full diff for a commit"""
        return self._run_git("show", commit_sha)
    
    def get_commits_for_tag(self, tag: str, previous_tag: Optional[str] = None) -> List[str]:
        """Get list of commit SHAs between tags or up to a tag"""
        if previous_tag:
            # Get commits between two tags
            range_spec = f"{previous_tag}..{tag}"
        else:
            # Get all commits up to tag
            range_spec = tag
        
        output = self._run_git("rev-list", range_spec)
        return output.split('\n') if output else []
    
    def build_contributor_profiles(self, commit_shas: List[str]) -> None:
        """Build contributor profiles from a list of commits"""
        self.contributors.clear()
        
        for sha in commit_shas:
            metadata = self.get_commit_metadata(sha)
            email = metadata.author_email
            
            if email not in self.contributors:
                self.contributors[email] = ContributorProfile(
                    name=metadata.author_name,
                    email=email
                )
            
            profile = self.contributors[email]
            profile.total_commits += 1
            profile.commit_messages.append(metadata.message)
            
            if profile.first_commit_date is None or metadata.date < profile.first_commit_date:
                profile.first_commit_date = metadata.date
            if profile.last_commit_date is None or metadata.date > profile.last_commit_date:
                profile.last_commit_date = metadata.date
            
            # Track files touched
            changes = self.get_file_changes(sha)
            for change in changes:
                profile.files_touched.add(change.filename)


class SensitiveFileDetector:
    """Detects sensitive files based on patterns"""
    
    # Patterns based on Anomalicious paper
    SENSITIVE_PATTERNS = [
        # Package/build files
        r'package\.json$',
        r'package-lock\.json$',
        r'yarn\.lock$',
        r'\.npmrc$',
        r'\.npmignore$',
        
        # Build/config files
        r'webpack\.config\.(js|ts)$',
        r'rollup\.config\.(js|ts)$',
        r'tsconfig\.json$',
        r'babel\.config\.(js|json)$',
        r'\.babelrc$',
        
        # CI/CD files
        r'\.github/workflows/',
        r'\.travis\.yml$',
        r'\.gitlab-ci\.yml$',
        r'Jenkinsfile$',
        
        # Security/Auth
        r'\.env$',
        r'\.env\.',
        r'config/.*\.(json|yml|yaml)$',
        
        # Installation/setup scripts
        r'install\.(sh|js)$',
        r'setup\.(sh|js)$',
        r'postinstall\.(sh|js)$',
        r'preinstall\.(sh|js)$',
    ]
    
    @classmethod
    def is_sensitive(cls, filename: str) -> bool:
        """Check if a file is considered sensitive"""
        for pattern in cls.SENSITIVE_PATTERNS:
            if re.search(pattern, filename, re.IGNORECASE):
                return True
        return False


class PreAnalyzer:
    """Pre-analysis phase: analyze metadata, contributors, and changes"""
    
    def __init__(self, repo: Repository):
        self.repo = repo
        self.findings: List[str] = []
        self.commit_shas: List[str] = []
    
    def analyze_version(self, tag: str, previous_tag: Optional[str] = None) -> Dict:
        """
        Perform pre-analysis on a specific version tag
        Returns structured analysis report
        """
        self.findings.clear()
        
        self.findings.append(f"=== PRE-ANALYSIS REPORT FOR VERSION {tag} ===\n")
        self.findings.append(f"Repository: {self.repo.name}")
        self.findings.append(f"Analysis Date: {datetime.now().isoformat()}\n")
        
        # Get commits for this version
        self.commit_shas = self.repo.get_commits_for_tag(tag, previous_tag)
        self.findings.append(f"Total commits analyzed: {len(self.commit_shas)}")
        
        if previous_tag:
            self.findings.append(f"Commit range: {previous_tag} -> {tag}\n")
        else:
            self.findings.append(f"All commits up to: {tag}\n")
        
        # Build contributor profiles
        self.repo.build_contributor_profiles(self.commit_shas)
        
        # 1. Analyze metadata (files, packages, build configs)
        metadata_results = self._analyze_metadata(self.commit_shas)
        
        # 2. Analyze contributor trust
        contributor_results = self._analyze_contributors()
        
        # 3. Analyze code and library changes
        change_results = self._analyze_changes(self.commit_shas)
        
        self.findings.append(f"\n--- END OF PRE-ANALYSIS ---")
        
        # Return structured data for LangGraph state
        return {
            'report_text': '\n'.join(self.findings),
            'commit_shas': self.commit_shas,
            'metadata_results': metadata_results,
            'contributor_results': contributor_results,
            'change_results': change_results
        }
    
    def _analyze_metadata(self, commit_shas: List[str]) -> Dict:
        """Analyze repository metadata and important files"""
        self.findings.append("\n--- 1. METADATA ANALYSIS ---\n")
        
        sensitive_files: Dict[str, List[str]] = {}  # filename -> [commit_shas]
        all_files_changed: Set[str] = set()
        
        for sha in commit_shas:
            changes = self.repo.get_file_changes(sha)
            for change in changes:
                all_files_changed.add(change.filename)
                
                if SensitiveFileDetector.is_sensitive(change.filename):
                    change.is_sensitive = True
                    if change.filename not in sensitive_files:
                        sensitive_files[change.filename] = []
                    sensitive_files[change.filename].append(sha[:8])
        
        self.findings.append(f"Total unique files changed: {len(all_files_changed)}")
        self.findings.append(f"Sensitive files modified: {len(sensitive_files)}")
        
        if sensitive_files:
            self.findings.append("\nSensitive file modifications:")
            for filename, commits in sensitive_files.items():
                self.findings.append(f"  - {filename} (modified in {len(commits)} commit(s): {', '.join(commits)})")
        
        # Check for package.json changes
        if 'package.json' in sensitive_files:
            self.findings.append("\n⚠️  ALERT: package.json was modified - check for dependency changes")
        
        # Check for build script changes
        build_scripts = [f for f in sensitive_files.keys() if 'install' in f or 'setup' in f]
        if build_scripts:
            self.findings.append(f"\n⚠️  ALERT: Build/install scripts modified: {', '.join(build_scripts)}")
        
        return {
            'sensitive_files': sensitive_files,
            'all_files_changed': list(all_files_changed),
            'total_files': len(all_files_changed)
        }
    
    def _analyze_contributors(self) -> Dict:
        """Analyze contributor trust levels"""
        self.findings.append("\n--- 2. CONTRIBUTOR TRUST ANALYSIS ---\n")
        
        self.findings.append(f"Total contributors: {len(self.repo.contributors)}")
        
        # Categorize contributors
        new_contributors = []
        trusted_contributors = []
        suspicious_contributors = []
        
        for email, profile in self.repo.contributors.items():
            if profile.is_new_contributor:
                new_contributors.append(profile)
            
            if profile.trust_score >= 0.7:
                trusted_contributors.append(profile)
            elif profile.trust_score < 0.3:
                suspicious_contributors.append(profile)
        
        self.findings.append(f"Trusted contributors (trust >= 0.7): {len(trusted_contributors)}")
        self.findings.append(f"New contributors (< 5 commits): {len(new_contributors)}")
        self.findings.append(f"Low-trust contributors (trust < 0.3): {len(suspicious_contributors)}")
        
        if new_contributors:
            self.findings.append("\nNew contributors:")
            for profile in new_contributors:
                self.findings.append(f"  - {profile.name} <{profile.email}> ({profile.total_commits} commit(s))")
        
        if suspicious_contributors:
            self.findings.append("\n⚠️  Low-trust contributors:")
            for profile in suspicious_contributors:
                self.findings.append(
                    f"  - {profile.name} <{profile.email}> "
                    f"(trust: {profile.trust_score:.2f}, commits: {profile.total_commits})"
                )
        
        return {
            'new_contributors': [{'name': p.name, 'email': p.email, 'commits': p.total_commits} for p in new_contributors],
            'suspicious_contributors': [{'name': p.name, 'email': p.email, 'trust': p.trust_score} for p in suspicious_contributors]
        }
    
    def _analyze_changes(self, commit_shas: List[str]) -> Dict:
        """Analyze code and library changes"""
        self.findings.append("\n--- 3. CODE AND LIBRARY CHANGES ANALYSIS ---\n")
        
        total_additions = 0
        total_deletions = 0
        commits_with_large_changes = []
        dependency_changes = []
        
        for sha in commit_shas:
            metadata = self.repo.get_commit_metadata(sha)
            changes = self.repo.get_file_changes(sha)
            
            commit_additions = sum(c.additions for c in changes)
            commit_deletions = sum(c.deletions for c in changes)
            
            total_additions += commit_additions
            total_deletions += commit_deletions
            
            # Detect outlier commits (unusually large changes)
            if commit_additions + commit_deletions > 500:
                commits_with_large_changes.append({
                    'sha': sha[:8],
                    'author': metadata.author_name,
                    'changes': commit_additions + commit_deletions,
                    'files': len(changes)
                })
            
            # Check for dependency changes
            for change in changes:
                if change.filename in ['package.json', 'package-lock.json', 'yarn.lock']:
                    dependency_changes.append({
                        'sha': sha[:8],
                        'file': change.filename,
                        'author': metadata.author_name,
                        'additions': change.additions,
                        'deletions': change.deletions
                    })
        
        self.findings.append(f"Total lines added: {total_additions}")
        self.findings.append(f"Total lines deleted: {total_deletions}")
        self.findings.append(f"Net change: {total_additions - total_deletions:+d} lines")
        
        if commits_with_large_changes:
            self.findings.append(f"\n⚠️  Commits with large changes (>500 lines):")
            for commit in commits_with_large_changes:
                self.findings.append(
                    f"  - {commit['sha']} by {commit['author']}: "
                    f"{commit['changes']} lines across {commit['files']} files"
                )
        
        if dependency_changes:
            self.findings.append(f"\n🔍 Dependency changes detected:")
            for dep in dependency_changes:
                self.findings.append(
                    f"  - {dep['sha']} modified {dep['file']} by {dep['author']} "
                    f"(+{dep['additions']}/-{dep['deletions']})"
                )
        
        return {
            'total_additions': total_additions,
            'total_deletions': total_deletions,
            'large_commits': commits_with_large_changes,
            'dependency_changes': dependency_changes
        }
