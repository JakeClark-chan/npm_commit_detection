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
from typing import Dict, List, Optional
from dataclasses import dataclass, field

import tiktoken
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate


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
        """Initialize static analyzer with LLM"""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        
        # Read configuration from environment
        self.model_name = model_name or os.getenv("LLM_MODEL", "gpt-4o-mini")
        self.context_window = int(os.getenv("LLM_CONTEXT_WINDOW", "128000"))
        self.max_output_tokens = 4000
        self.max_retries = 3  # Maximum retry attempts for failed LLM calls
        
        # Calculate max input tokens (reserve space for output and system prompt)
        self.max_input_tokens = self.context_window - self.max_output_tokens - 2000
        
        self.llm = ChatOpenAI(
            model=self.model_name,
            temperature=0.1,  # Low temperature for more consistent analysis
            max_tokens=self.max_output_tokens
        )
        
        # Initialize tokenizer for the model
        try:
            self.tokenizer = tiktoken.encoding_for_model(self.model_name)
        except KeyError:
            # Fallback to cl100k_base encoding (used by gpt-4, gpt-3.5-turbo)
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
        
        self.issues: List[SecurityIssue] = []
        self.import_analyses: List[ImportAnalysis] = []
    
    def analyze_commits(self, repository, commit_shas: List[str]) -> Dict:
        """
        Analyze a list of commits for security issues
        
        Args:
            repository: Repository object from pre_analysis
            commit_shas: List of commit SHAs to analyze
        
        Returns:
            Dictionary with analysis results
        """
        self.issues.clear()
        self.import_analyses.clear()
        
        print(f"\n🔍 Starting static analysis of {len(commit_shas)} commits...")
        
        for idx, sha in enumerate(commit_shas, 1):
            print(f"  Analyzing commit {idx}/{len(commit_shas)}: {sha[:8]}...")
            
            try:
                # Get commit metadata and diff
                metadata = repository.get_commit_metadata(sha)
                changes = repository.get_file_changes(sha)
                diff = repository.get_commit_diff(sha)
                
                # Analyze imports
                self._analyze_imports(sha, diff)
                
                # Pattern-based detection (fast)
                suspicious_patterns = self._detect_suspicious_patterns(sha, diff)
                
                # LLM-based deep analysis (for commits with changes or suspicious patterns)
                if changes or suspicious_patterns:
                    self._llm_analyze_commit_with_chunking(sha, metadata, changes, diff, suspicious_patterns)
                    
            except Exception as e:
                print(f"    ⚠️  Error analyzing commit {sha[:8]}: {e}")
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
        suspicious_patterns: Dict[str, List[str]]
    ) -> None:
        """Analyze commit with automatic chunking for large diffs"""
        
        # Prepare base context (without diff)
        base_context = self._prepare_base_context(commit_sha, metadata, changes, suspicious_patterns)
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
            print(f"    🔀 Splitting into {len(chunks)} chunks")
            
            previous_summary = ""
            for idx, chunk in enumerate(chunks, 1):
                chunk_tokens = self._count_tokens(chunk)
                print(f"    📦 Analyzing chunk {idx}/{len(chunks)} ({chunk_tokens} tokens)...")
                
                self._llm_analyze_commit(
                    commit_sha, 
                    metadata, 
                    changes, 
                    chunk, 
                    suspicious_patterns, 
                    base_context,
                    chunk_index=idx,
                    total_chunks=len(chunks),
                    previous_summary=previous_summary
                )
                
                # Generate summary for next chunk
                if idx < len(chunks):
                    previous_summary = f"Previous chunk {idx} analysis completed. Continue analyzing remaining code."
    
    def _prepare_base_context(
        self,
        commit_sha: str,
        metadata,
        changes: List,
        suspicious_patterns: Dict[str, List[str]]
    ) -> str:
        """Prepare base context without diff"""
        context_parts = [
            f"Commit: {commit_sha[:8]}",
            f"Author: {metadata.author_name} <{metadata.author_email}>",
            f"Date: {metadata.date}",
            f"Message: {metadata.message}",
            f"\nFiles changed: {len(changes)}"
        ]
        
        for change in changes[:10]:  # Show more files now
            context_parts.append(
                f"  - {change.filename} ({change.status}): "
                f"+{change.additions}/-{change.deletions}"
            )
        
        if len(changes) > 10:
            context_parts.append(f"  ... and {len(changes) - 10} more files")
        
        if suspicious_patterns:
            context_parts.append("\nSuspicious patterns detected:")
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
        system_prompt = """You are a security expert analyzing code commits for potential vulnerabilities and malicious behavior.

Your task is to analyze the provided commit and identify security issues in these categories:

1. **Code Injection**: eval(), Function(), vm.runInNewContext, etc.
2. **Suspicious Network Access**: Unexpected HTTP requests, data exfiltration to external servers
3. **Data Leaks**: Exposure of sensitive data, credentials, tokens
4. **Unsafe Environment Variables**: Accessing or exposing process.env variables unsafely
5. **Crypto Activities**: Bitcoin, Ethereum, wallet operations, mining
6. **Command Execution**: child_process, exec(), spawn() with untrusted input
7. **Obfuscation**: Hex encoding, base64, String.fromCharCode chains

For each issue found, provide:
- Severity (CRITICAL, HIGH, MEDIUM, LOW)
- Category
- File path (extract from diff header, e.g., "diff --git a/src/file.js")
- Line number (if identifiable)
- Description
- Code snippet
- Recommendation

Respond in JSON format:
{
  "issues": [
    {
      "severity": "HIGH",
      "category": "code_injection",
      "file": "src/utils.js",
      "line": 42,
      "description": "...",
      "code_snippet": "...",
      "recommendation": "..."
    }
  ],
  "summary": "Brief summary of findings"
}

If no issues found, return {"issues": [], "summary": "No security issues detected"}."""

        chunk_info = f" (chunk {chunk_index}/{total_chunks})" if total_chunks > 1 else ""
        user_prompt = f"""Analyze this commit{chunk_info} for security vulnerabilities:

{context}

Respond in JSON format as specified."""

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
                    user_prompt = f"""The previous response was not valid JSON. Please analyze this commit{chunk_info} and respond ONLY with valid JSON in this exact format:

{{
  "issues": [
    {{
      "severity": "HIGH",
      "category": "code_injection",
      "file": "path/to/file.js",
      "line": 42,
      "description": "Description of the issue",
      "code_snippet": "problematic code",
      "recommendation": "How to fix it"
    }}
  ],
  "summary": "Brief summary of findings"
}}

Commit to analyze:
{context}

Respond ONLY with valid JSON, no markdown formatting, no extra text."""
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
        """Generate human-readable report from analysis results"""
        lines = [
            "\n" + "="*80,
            "STATIC ANALYSIS REPORT",
            "="*80,
            f"\nTotal Security Issues Found: {analysis_results['total_issues']}",
        ]
        
        # Severity breakdown
        lines.append("\nIssues by Severity:")
        for severity, count in analysis_results['issues_by_severity'].items():
            if count > 0:
                lines.append(f"  {severity}: {count}")
        
        # Category breakdown
        lines.append("\nIssues by Category:")
        for category, count in analysis_results['issues_by_category'].items():
            lines.append(f"  {category}: {count}")
        
        # Import analysis
        if self.import_analyses:
            lines.append(f"\nImport Analysis:")
            suspicious_imports = sum(len(a.suspicious_imports) for a in self.import_analyses)
            if suspicious_imports > 0:
                lines.append(f"  ⚠️  Suspicious imports detected: {suspicious_imports}")
        
        # Detailed issues
        if self.issues:
            lines.append("\n" + "-"*80)
            lines.append("DETAILED ISSUES")
            lines.append("-"*80)
            
            for idx, issue in enumerate(self.issues, 1):
                lines.append(f"\n[{idx}] {issue.severity} - {issue.category}")
                lines.append(f"    Commit: {issue.commit_sha[:8]}")
                lines.append(f"    File: {issue.file_path}")
                if issue.line_number:
                    lines.append(f"    Line: {issue.line_number}")
                lines.append(f"    Description: {issue.description}")
                if issue.code_snippet:
                    lines.append(f"    Code: {issue.code_snippet[:100]}...")
                lines.append(f"    Recommendation: {issue.recommendation}")
        
        lines.append("\n" + "="*80)
        lines.append("END OF STATIC ANALYSIS REPORT")
        lines.append("="*80 + "\n")
        
        return '\n'.join(lines)
