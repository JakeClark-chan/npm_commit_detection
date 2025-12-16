#!/usr/bin/env python3
"""
Static Analysis Module using OpenAI LLM
Analyzes code for security vulnerabilities and suspicious patterns

Tasks:
- Tìm lỗ hổng và phân tích tĩnh (Find vulnerabilities and static analysis)
- Quét lịch sử commit (Scan commit history)
- Mở rộng thư viện dựa trên các lời gọi import (Expand libraries based on imports)
- LLM phân tích code, đặc biệt là các commit chứa code mới và đã chỉnh sửa
  (LLM analyzes code, especially commits with new and modified code)
  
Detects:
- Code injection
- Truy cập đến địa chỉ nghi ngờ (Access to suspicious addresses)
- Làm lộ dữ liệu (Data leaks/exfiltration)
- Sử dụng biến môi trường không an toàn (Unsafe environment variable usage)
- Hoạt động crypto (Crypto-related activities)
- And more...
"""

import os
import re
import time
import subprocess
import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field

import tiktoken
from langchain_core.messages import HumanMessage, SystemMessage

from configs.static_config import StaticAnalysisConfig
from configs.llm_config import LLMConfig
from llm.service import LLMService
import prompts.static_prompts as prompts

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class SecurityIssue:
    """Represents a security issue found in code"""
    severity: str  # critical, high, medium, low
    category: str  # code_injection, data_leak, suspicious_network, etc.
    commit_sha: str
    file_path: str
    line_number: Optional[int]
    description: str
    code_snippet: str
    recommendation: str


@dataclass
class ImportAnalysis:
    """Analysis of imports and dependencies"""
    commit_sha: str
    file_path: str
    imports: List[str]
    suspicious_imports: List[str] = field(default_factory=list)
    unknown_packages: List[str] = field(default_factory=list)


class StaticAnalyzer:
    """
    Static analysis using OpenAI LLM to detect security issues
    """
    
    # Suspicious patterns to look for
    SUSPICIOUS_PATTERNS = {
        'network': [
            r'https?://[^\s\'"]+',  # URLs
            r'fetch\s*\(',
            r'axios\.',
            r'http\.get',
            r'http\.post',
            r'XMLHttpRequest',
        ],
        'crypto': [
            r'crypto\.createHash',
            r'bitcoin',
            r'ethereum',
            r'wallet',
            r'private.*key',
            r'mnemonic',
        ],
        'env': [
            r'process\.env\.',
            r'ENV\[',
            r'getenv\(',
        ],
        'eval': [
            r'\beval\s*\(',
            r'Function\s*\(',
            r'vm\.runInNewContext',
            r'child_process',
            r'exec\s*\(',
            r'spawn\s*\(',
        ],
        'obfuscation': [
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'String\.fromCharCode',
            r'atob\s*\(',
            r'Buffer\.from.*base64',
        ]
    }
    
    def __init__(self, model_name: str = None):
        """
        Initialize static analyzer with LLM configuration.
        
        Args:
            model_name: Name of the LLM model to use (default: env var or gpt-4o-mini)
        """
        # Read configuration from Config classes
        self.model_name = model_name or StaticAnalysisConfig.MODEL
        self.context_window = StaticAnalysisConfig.CONTEXT_WINDOW
        
        self.max_output_tokens = 4000 # Could be moved to config if needed
        self.max_retries = 3
        self.temperature = StaticAnalysisConfig.TEMPERATURE
        self.concurrent_threads = LLMConfig.CONCURRENT_THREADS
        
        # Calculate max input tokens (reserve space for output and system prompt)
        self.max_input_tokens = self.context_window - self.max_output_tokens - 2000
        
        self.llm = LLMService.get_llm(
            model_name=self.model_name,
            temperature=self.temperature
        )
        
        # Initialize tokenizer for the model used for token counting
        try:
            self.tokenizer = tiktoken.encoding_for_model(self.model_name)
        except KeyError:
            # Fallback to cl100k_base encoding (used by gpt-4, gpt-3.5-turbo)
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
        
        self.issues: List[SecurityIssue] = []
        self.import_analyses: List[ImportAnalysis] = []
        
        # Path to the deobfuscation tool script
        self.deobfuscator_script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
            "tools", 
            "deobfuscate.js"
        )

    def _deobfuscate_code(self, code: str) -> str:
        """
        Attempt to deobfuscate code using the de4js wrapper tool.
        Returns the deobfuscated code or the original if failed/no change.
        """
        try:
            # Use node to run the deobfuscator
            process = subprocess.Popen(
                ["node", self.deobfuscator_script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=code)
            
            if process.returncode != 0:
                logger.warning(f"Deobfuscation failed: {stderr}")
                return code
            
            # If output is significantly different, return it
            return stdout.strip() if stdout.strip() else code
            
        except Exception as e:
            logger.error(f"Error running deobfuscator: {e}")
            return code
    
    def analyze_commits(self, repository, commit_shas: List[str]) -> Dict:
        """
        Analyze a list of commits for security issues.
        Analysis is performed per-file for each commit diff.
        
        Args:
            repository: Repository object from pre_analysis
            commit_shas: List of commit SHAs to analyze
        
        Returns:
            Dictionary with analysis results
        """
        self.issues.clear()
        self.import_analyses.clear()
        
        print(f"\n🔍 Starting static analysis of {len(commit_shas)} commits...")
        print(f"   ⚙️  Configuration: {self.concurrent_threads} threads, Model: {self.model_name}")
        
        for idx, sha in enumerate(commit_shas, 1):
            print(f"  Analyzing commit {idx}/{len(commit_shas)}: {sha[:8]}...")
            
            try:
                # Get commit metadata
                metadata = repository.get_commit_metadata(sha)
                changes = repository.get_file_changes(sha)
                full_diff = repository.get_commit_diff(sha) # Still get full diff for pattern scanning context or import analysis if needed?
                # Actually import analysis currently runs on 'diff'. It might be better to run it per file too, 
                # but for now let's keep pattern scanning on the full diff or per file?
                # The prompt asks for "generate multiple requests for each file diff inside static analysis".
                # Let's do per-file analysis for the LLM part.
                
                # Analyze imports (global for commit for now)
                self._analyze_imports(sha, full_diff)
                
                # Pattern-based detection (fast - global)
                suspicious_patterns_global = self._detect_suspicious_patterns(sha, full_diff)
                
                # If no changes, skip
                if not changes:
                    continue

                print(f"    - Found {len(changes)} changed files in {sha[:8]}")

                # Process each file
                # Ideally we parallelize this if there are many files in one commit? 
                # `_llm_analyze_commit_with_chunking` logic might need adjustment.
                # Let's call a modified version or just iterate.
                
                from concurrent.futures import ThreadPoolExecutor, as_completed
                
                # We can reuse the thread pool if we want parallel files analysis
                with ThreadPoolExecutor(max_workers=self.concurrent_threads) as executor:
                    futures = []
                    
                    for change in changes:
                        filename = change.filename
                        if change.status == 'D': # Deleted
                            continue
                            
                        # Get specific file diff
                        file_diff = repository.get_file_diff(sha, filename)
                        if not file_diff or not file_diff.strip():
                            continue
                            
                        # Pattern detection for this file specifically? 
                        # We passed global patterns before. Let's enable LLM analysis for *this file*.
                        
                        # We need to adapt _llm_analyze_commit_with_chunking to take file_diff
                        # and maybe file path context.
                        
                        # Check obfuscation
                        if 'obfuscation' in suspicious_patterns_global:
                             # Try deobfuscate this file
                             deobf = self._deobfuscate_code(file_diff)
                             if deobf != file_diff:
                                 file_diff = deobf
                        
                        # Schedule analysis
                        futures.append(executor.submit(
                            self._llm_analyze_commit_with_chunking,
                            sha,
                            metadata,
                            [change], # Pass just this change for context
                            file_diff,
                            suspicious_patterns_global, # Pass global patterns? Or should we find patterns in this file?
                            # Let's pass global patterns for context, LLM can see if they apply.
                            filename # New arg for context
                        ))
                    
                    # Wait for completion
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            print(f"    ⚠️  Error analyzing file in {sha[:8]}: {e}")

            except Exception as e:
                print(f"    ⚠️  Error analyzing commit {sha[:8]}: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        print(f"✅ Static analysis complete. Found {len(self.issues)} issues.\n")
        
        return {
            'total_issues': len(self.issues),
            'issues_by_severity': self._categorize_by_severity(),
            'issues_by_category': self._categorize_by_type(),
            'all_issues': self.issues,
            'import_analyses': self.import_analyses
        }
    
    def _analyze_imports(self, commit_sha: str, diff: str) -> None:
        """Analyze imports and dependencies in the diff"""
        # Extract imports from JavaScript/TypeScript files
        import_patterns = [
            r'import\s+.*\s+from\s+[\'"]([^\'"]+)[\'"]',  # ES6 imports
            r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',  # CommonJS require
            r'import\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',   # Dynamic imports
        ]
        
        all_imports = set()
        for pattern in import_patterns:
            matches = re.findall(pattern, diff)
            all_imports.update(matches)
        
        if all_imports:
            # Check for suspicious imports
            suspicious = []
            for imp in all_imports:
                if self._is_suspicious_import(imp):
                    suspicious.append(imp)
            
            analysis = ImportAnalysis(
                commit_sha=commit_sha,
                file_path="<multiple>",
                imports=list(all_imports),
                suspicious_imports=suspicious
            )
            self.import_analyses.append(analysis)
    
    def _is_suspicious_import(self, import_name: str) -> bool:
        """Check if an import is suspicious"""
        suspicious_keywords = [
            'eval', 'vm', 'child_process', 'exec',
            'http', 'https', 'request', 'axios', 'fetch',
            'crypto', 'bitcoin', 'ethereum',
            'obfuscator', 'uglify'
        ]
        
        import_lower = import_name.lower()
        return any(keyword in import_lower for keyword in suspicious_keywords)
    
    def _detect_suspicious_patterns(self, commit_sha: str, diff: str) -> Dict[str, List[str]]:
        """Fast pattern-based detection of suspicious code"""
        findings = {}
        
        for category, patterns in self.SUSPICIOUS_PATTERNS.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, diff, re.IGNORECASE)
                matches.extend(found)
            
            if matches:
                findings[category] = list(set(matches))  # Deduplicate
        
        return findings
    
    def _count_tokens(self, text: str) -> int:
        """Count tokens in text using tiktoken"""
        return len(self.tokenizer.encode(text))
    
    def _split_diff_into_chunks(self, diff: str, max_chunk_size: int) -> List[str]:
        """Split diff into chunks based on file boundaries and token limits"""
        chunks = []
        current_chunk = []
        current_tokens = 0
        
        # Split diff by file headers
        file_pattern = re.compile(r'^diff --git a/', re.MULTILINE)
        parts = file_pattern.split(diff)
        
        # First part might be empty or commit header
        if parts and not parts[0].strip():
            parts = parts[1:]
        
        for i, part in enumerate(parts):
            if not part.strip():
                continue
                
            # Reconstruct the diff header
            file_diff = "diff --git a/" + part if i > 0 or parts[0].strip() else part
            file_tokens = self._count_tokens(file_diff)
            
            # If single file is too large, split it further
            if file_tokens > max_chunk_size:
                # Split by hunks (@@)
                hunk_pattern = re.compile(r'(@@[^@]+@@)', re.MULTILINE)
                hunks = hunk_pattern.split(file_diff)
                
                file_header = hunks[0] if hunks else ""
                for j in range(1, len(hunks), 2):
                    if j + 1 < len(hunks):
                        hunk = hunks[j] + hunks[j + 1]
                        hunk_tokens = self._count_tokens(file_header + hunk)
                        
                        if current_tokens + hunk_tokens > max_chunk_size and current_chunk:
                            chunks.append(''.join(current_chunk))
                            current_chunk = [file_header, hunk]
                            current_tokens = hunk_tokens
                        else:
                            current_chunk.append(hunk)
                            current_tokens += hunk_tokens
            else:
                # Check if adding this file exceeds chunk size
                if current_tokens + file_tokens > max_chunk_size and current_chunk:
                    chunks.append(''.join(current_chunk))
                    current_chunk = [file_diff]
                    current_tokens = file_tokens
                else:
                    current_chunk.append(file_diff)
                    current_tokens += file_tokens
        
        # Add remaining chunk
        if current_chunk:
            chunks.append(''.join(current_chunk))
        
        return chunks if chunks else [diff]
    
    def _llm_analyze_commit_with_chunking(
        self,
        commit_sha: str,
        metadata,
        changes: List,
        diff: str,
        suspicious_patterns: Dict[str, List[str]],
        filename: str = None
    ) -> None:
        """Analyze commit (or specific file) with automatic parallel chunking for large diffs"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        # Prepare base context (without diff)
        base_context = self._prepare_base_context(commit_sha, metadata, changes, suspicious_patterns, filename)
        base_tokens = self._count_tokens(base_context)
        
        # Calculate available tokens for diff
        system_prompt_tokens = 500  # Approximate
        available_tokens = self.max_input_tokens - base_tokens - system_prompt_tokens
        
        print(f"    📊 Base context: {base_tokens} tokens, Available for diff: {available_tokens} tokens")
        
        # Split diff if needed
        diff_tokens = self._count_tokens(diff)
        print(f"    📄 Diff size: {diff_tokens} tokens")
        
        if diff_tokens <= available_tokens:
            # Single request
            print(f"    ✅ Processing in single request")
            self._llm_analyze_commit(commit_sha, metadata, changes, diff, suspicious_patterns, base_context)
        else:
            # Multiple requests with chunking
            chunks = self._split_diff_into_chunks(diff, available_tokens)
            print(f"    🔀 Splitting into {len(chunks)} chunks, processing with {self.concurrent_threads} threads parallel...")
            
            with ThreadPoolExecutor(max_workers=self.concurrent_threads) as executor:
                futures = []
                for idx, chunk in enumerate(chunks, 1):
                    chunk_tokens = self._count_tokens(chunk)
                    print(f"    📦 Scheduling chunk {idx}/{len(chunks)} ({chunk_tokens} tokens)...")
                    
                    futures.append(executor.submit(
                        self._llm_analyze_commit,
                        commit_sha, 
                        metadata, 
                        changes, 
                        chunk, 
                        suspicious_patterns, 
                        base_context,
                        chunk_index=idx,
                        total_chunks=len(chunks),
                        previous_summary=""  # Parallel execution cannot have previous summary
                    ))
                
                # Wait for all chunks to complete
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"    ⚠️  Chunk analysis failed: {e}")
    
    def _prepare_base_context(
        self,
        commit_sha: str,
        metadata,
        changes: List,
        suspicious_patterns: Dict[str, List[str]],
        filename: str = None
    ) -> str:
        """Prepare base context without diff"""
        context_parts = [
            f"Commit: {commit_sha[:8]}",
            f"Author: {metadata.author_name} <{metadata.author_email}>",
            f"Date: {metadata.date}",
            f"Message: {metadata.message}",
        ]
        
        if filename:
             context_parts.append(f"\nAnalyzing specific file: {filename}")
             # We can still list other files changed for context if we want
             context_parts.append(f"Total files changed in commit: {len(changes)}")
        else:
             context_parts.append(f"\nFiles changed: {len(changes)}")
        
        for change in changes[:10]:  # Show more files now
            context_parts.append(
                f"  - {change.filename} ({change.status}): "
                f"+{change.additions}/-{change.deletions}"
            )
        
        if len(changes) > 10:
            context_parts.append(f"  ... and {len(changes) - 10} more files")
        
        if suspicious_patterns:
            context_parts.append("\nSuspicious patterns detected (in full commit):")
            for category, matches in suspicious_patterns.items():
                context_parts.append(f"  - {category}: {', '.join(matches[:5])}")
        
        return '\n'.join(context_parts)
    
    def _llm_analyze_commit(
        self,
        commit_sha: str,
        metadata,
        changes: List,
        diff: str,
        suspicious_patterns: Dict[str, List[str]],
        base_context: str = None,
        chunk_index: int = 1,
        total_chunks: int = 1,
        previous_summary: str = ""
    ) -> None:
        """Use LLM to perform deep analysis of a commit or chunk"""
        
        # Prepare context for LLM
        if base_context is None:
            base_context = self._prepare_base_context(commit_sha, metadata, changes, suspicious_patterns)
        
        context_parts = [base_context]
        
        if total_chunks > 1:
            context_parts.append(f"\n--- ANALYZING CHUNK {chunk_index} of {total_chunks} ---")
            if previous_summary:
                context_parts.append(f"Previous analysis: {previous_summary}")
        
        context_parts.append("\n--- CODE DIFF ---")
        context_parts.append(diff)
        
        context = '\n'.join(context_parts)
        
        # Create prompt
        system_prompt = prompts.SYSTEM_PROMPT

        chunk_info = f" (chunk {chunk_index}/{total_chunks})" if total_chunks > 1 else ""
        user_prompt = prompts.USER_PROMPT_TEMPLATE.format(
            chunk_info=chunk_info,
            context=context
        )

        # Retry logic for LLM calls
        for attempt in range(self.max_retries):
            try:
                # Call LLM
                messages = [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=user_prompt)
                ]
                
                response = self.llm.invoke(messages)
                
                # Validate response has content
                if not response.content or not response.content.strip():
                    raise ValueError("Empty response from LLM")
                
                # Try to parse response
                parsed = self._parse_llm_response(commit_sha, response.content, diff)
                
                # If parsing succeeded, break retry loop
                if parsed:
                    break
                    
                # If parsing failed, retry with correction prompt
                if attempt < self.max_retries - 1:
                    print(f"    🔄 Retry {attempt + 1}/{self.max_retries - 1}: Invalid JSON format, retrying...")
                    user_prompt = prompts.JSON_RETRY_PROMPT_TEMPLATE.format(
                        chunk_info=chunk_info,
                        context=context
                    )
                    time.sleep(1)  # Brief delay before retry
                else:
                    print(f"    ❌ Failed after {self.max_retries} attempts for {commit_sha[:8]}{chunk_info}")
                
            except Exception as e:
                if attempt < self.max_retries - 1:
                    print(f"    🔄 Retry {attempt + 1}/{self.max_retries - 1}: Error {type(e).__name__}: {str(e)[:100]}")
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    print(f"    ⚠️  LLM analysis error for {commit_sha[:8]}{chunk_info} after {self.max_retries} attempts: {e}")
    
    def _resolve_file_path(self, code_snippet: str, diff: str) -> str:
        """Resolve file path from code snippet using the diff"""
        if not code_snippet or len(code_snippet) < 5:
            return "unknown"
            
        # Try to find the snippet in the diff
        snippet_idx = diff.find(code_snippet)
        if snippet_idx == -1:
            # Try finding a substring if full snippet not found
            snippet_idx = diff.find(code_snippet[:20])
            
        if snippet_idx != -1:
            # Search backwards for "diff --git a/"
            file_header_idx = diff.rfind("diff --git a/", 0, snippet_idx)
            if file_header_idx != -1:
                # Extract filename
                # Format: diff --git a/path/to/file b/path/to/file
                line_end = diff.find("\n", file_header_idx)
                header_line = diff[file_header_idx:line_end]
                parts = header_line.split(" b/")
                if len(parts) >= 2:
                    return parts[1].strip()
        
        return "unknown"

    def _parse_llm_response(self, commit_sha: str, response_text: str, diff: str) -> bool:
        """Parse LLM response and create SecurityIssue objects. Returns True if successful."""
        import json
        
        try:
            # Extract JSON from response (handle markdown code blocks)
            json_text = response_text
            if '```json' in response_text:
                json_text = response_text.split('```json')[1].split('```')[0]
            elif '```' in response_text:
                json_text = response_text.split('```')[1].split('```')[0]
            
            # Try to find JSON object even if surrounded by text
            json_text = json_text.strip()
            if not json_text.startswith('{'):
                # Try to find first { and last }
                start = json_text.find('{')
                end = json_text.rfind('}') + 1
                if start != -1 and end > start:
                    json_text = json_text[start:end]
            
            data = json.loads(json_text)
            
            # Validate required structure
            if not isinstance(data, dict):
                raise ValueError("Response is not a JSON object")
            if 'issues' not in data:
                raise ValueError("Response missing 'issues' field")
            if not isinstance(data['issues'], list):
                raise ValueError("'issues' field is not a list")
            
            for issue_data in data.get('issues', []):
                file_path = issue_data.get('file', 'unknown')
                code_snippet = issue_data.get('code_snippet', '')
                
                # Try to resolve file path if unknown or generic
                if file_path in ['unknown', ''] and code_snippet:
                    file_path = self._resolve_file_path(code_snippet, diff)
                
                issue = SecurityIssue(
                    severity=issue_data.get('severity', 'MEDIUM'),
                    category=issue_data.get('category', 'unknown'),
                    commit_sha=commit_sha,
                    file_path=file_path,
                    line_number=issue_data.get('line'),
                    description=issue_data.get('description', ''),
                    code_snippet=code_snippet,
                    recommendation=issue_data.get('recommendation', '')
                )
                self.issues.append(issue)
            
            return True  # Parsing successful
                
        except json.JSONDecodeError as e:
            print(f"    ⚠️  JSON decode error for {commit_sha[:8]}: {e}")
            return False
        except ValueError as e:
            print(f"    ⚠️  Invalid response format for {commit_sha[:8]}: {e}")
            return False
        except Exception as e:
            print(f"    ⚠️  Error processing LLM response for {commit_sha[:8]}: {e}")
            return False
    
    def _categorize_by_severity(self) -> Dict[str, int]:
        """Count issues by severity"""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for issue in self.issues:
            severity = issue.severity.upper()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _categorize_by_type(self) -> Dict[str, int]:
        """Count issues by category"""
        counts = {}
        for issue in self.issues:
            category = issue.category
            counts[category] = counts.get(category, 0) + 1
        return counts
    
    def generate_report(self, analysis_results: Dict) -> str:
        """
        Generate a professional executive summary report of the security analysis.
        
        Format:
        - Executive Summary
        - Detailed Commit Analysis (grouping issues by commit)
        - Statistical Footer
        """
        import datetime
        
        lines = [
            "SECURITY ASSESSMENT REPORT",
            f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "="*80,
            "\n1. EXECUTIVE SUMMARY",
            "-"*80,
            f"A comprehensive security analysis was performed on {self.model_name}.",
            f"Total Security Issues Identified: {analysis_results['total_issues']}",
        ]
        
        # Severity breakdown
        if analysis_results['issues_by_severity']:
            lines.append("\nSeverity Distribution:")
            for severity, count in analysis_results['issues_by_severity'].items():
                if count > 0:
                    lines.append(f"- {severity}: {count} issue(s)")
        
        # Import analysis summary
        if self.import_analyses:
            suspicious_imports = sum(len(a.suspicious_imports) for a in self.import_analyses)
            if suspicious_imports > 0:
                lines.append(f"\nObserved {suspicious_imports} suspicious external dependencies that warrant further investigation.")
        
        lines.append("\n2. DETAILED COMMIT ANALYSIS")
        lines.append("-" * 80)
        
        # Group issues by commit
        issues_by_commit = {}
        for issue in self.issues:
            if issue.commit_sha not in issues_by_commit:
                issues_by_commit[issue.commit_sha] = []
            issues_by_commit[issue.commit_sha].append(issue)
        
        suspicious_commits_count = len(issues_by_commit)
        
        if not issues_by_commit:
            lines.append("No significant security issues were detected in the analyzed commits.")
        else:
            for sha, issues in issues_by_commit.items():
                lines.append(f"\nCommit: {sha} (Issues: {len(issues)})")
                lines.append("." * 40)
                
                for issue in issues:
                    lines.append(f"  [{issue.severity}] {issue.category}")
                    lines.append(f"  File: {issue.file_path}")
                    if issue.line_number:
                        lines.append(f"  Line: {issue.line_number}")
                    lines.append(f"  Description: {issue.description}")
                    lines.append(f"  Recommendation: {issue.recommendation}")
                    lines.append("")
        
        lines.append("\n3. CONCLUSION & METRICS")
        lines.append("-" * 80)
        lines.append(f"Total Suspicious Commits: {suspicious_commits_count}")
        
        if suspicious_commits_count > 0:
             lines.append("Recommendation: Immediate review of the flagged commits is advised.")
        else:
             lines.append("Recommendation: Routine monitoring should continue.")

        lines.append("="*80)
        return '\n'.join(lines)

