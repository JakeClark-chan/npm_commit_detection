#!/usr/bin/env python3
"""
Verification Module - Compare Static and Dynamic Analysis Results
Uses LLM to normalize both analyses into unified schema and verify findings

Tasks:
- Kiểm tra và báo cáo (Verification and reporting)
- So sánh kết quả từ phân tích tĩnh và động (Compare static and dynamic analysis)
- LLM giải thích kết quả và đưa ra biện pháp (LLM explains results and provides remediation)
- LLM tạo ra một bản báo cáo hoàn chỉnh (LLM generates comprehensive report)
- Xuất báo cáo để người dùng xem xét (Export report for review)
"""

import os
import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage

from configs.llm_config import LLMConfig
from configs.dynamic_config import DynamicAnalysisConfig
from llm.service import LLMService
import prompts.verification_prompts as prompts
import logging

# Configure logging if run standalone
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

@dataclass
class NormalizedFinding:
    """Unified schema for static, dynamic, and snyk analysis findings"""
    finding_id: str
    source: str
    severity: str
    category: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    commit_sha: Optional[str] = None
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    verification_status: str = "UNVERIFIED"
    matched_finding_ids: List[str] = field(default_factory=list)
    # Dynamic specific
    command: Optional[str] = None
    process: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None

@dataclass
class VerificationResult:
    """Holistic result of verification process"""
    static_dynamic_matches: List[Tuple[NormalizedFinding, NormalizedFinding]] = field(default_factory=list)
    static_snyk_matches: List[Tuple[NormalizedFinding, NormalizedFinding]] = field(default_factory=list)
    snyk_dynamic_matches: List[Tuple[NormalizedFinding, NormalizedFinding]] = field(default_factory=list)
    
    suspicious_static_only: List[NormalizedFinding] = field(default_factory=list)
    suspicious_dynamic_only: List[NormalizedFinding] = field(default_factory=list)
    suspicious_snyk_only: List[NormalizedFinding] = field(default_factory=list)
    
    is_malicious: bool = False
    malicious_confidence: float = 0.0
    llm_analysis: str = ""
    comprehensive_report: str = ""

class DynamicAnalysisParser:
    """Parse dynamic analysis logs (Package Hunter)"""
    
    def parse_package_hunter_log(self, log_path: str) -> List[Dict]:
        """Parse JSON output from Package Hunter"""
        try:
            with open(log_path, 'r') as f:
                data = json.load(f)
            
            # Handle standard Package Hunter JSON report
            if isinstance(data, dict):
                # If wrapped in { status: ..., result: [...] }
                if 'result' in data and isinstance(data['result'], list):
                    return data['result']
                # If wrapped in { report: [...] } or similar (fallback)
                return []
            
            # If raw list
            if isinstance(data, list):
                return data
                
            return []
        except Exception as e:
            logger.error(f"Error parsing dynamic log: {e}")
            return []


class VerificationAnalyzer:
    """Verify and compare static vs dynamic analysis using LLM"""
    
    def __init__(self, verification_model: Optional[str] = None):
        # We can use specific env vars for verification model if we want, or default to what LLMConfig handles (if we added it there).
        # configs/llm_config.py has LLM_VERIFICATION_MODEL but I didn't put it in explicitly as a class attr yet?
        # Let's check configs/llm_config.py content again. I think I only put generic ones.
        # Actually I can just pass args to LLMService.
        
        # Accessing env vars via BaseConfig directly if they are not in LLMConfig is possible if I import BaseConfig
        # or just use os.getenv if I'm lazy, but I should try to be consistent.
        # Let's use os.getenv for now for these specific overrides if they are not in main config yet.
        model_name = verification_model or os.getenv("LLM_VERIFICATION_MODEL", "gpt-4o-mini")
        temp = float(os.getenv("LLM_VERIFICATION_TEMPERATURE", "1"))
        logger.info(f"🤖 Initializing verification LLM: {model_name} (temperature={temp})")
        
        self.llm = LLMService.get_llm(
            model_name=model_name,
            temperature=temp
        )
    
    def normalize_static_findings(self, static_analysis: Dict) -> List[NormalizedFinding]:
        """Normalize static analysis findings to unified schema"""
        logger.info("🔄 Normalizing static analysis findings...")
        
        normalized = []
        issues = static_analysis.get('static_analysis', {}).get('issues', [])
        
        # If passed directly as list (compat)
        if isinstance(issues, list) and len(issues) == 0 and 'issues' in static_analysis:
             issues = static_analysis.get('issues', [])

        for idx, issue in enumerate(issues):
            # Handle both dict and object (if coming from internal class)
            if hasattr(issue, 'severity'):
                severity = issue.severity
                category = issue.category
                file_path = issue.file_path
                line = issue.line_number
                desc = issue.description
                snippet = issue.code_snippet
                rec = issue.recommendation
                sha = issue.commit_sha
            else:
                severity = issue.get('severity', 'MEDIUM')
                category = issue.get('category', 'unknown')
                file_path = issue.get('file_path') or issue.get('file')
                line = issue.get('line_number') or issue.get('line')
                desc = issue.get('description', '')
                snippet = issue.get('code_snippet', '')
                rec = issue.get('recommendation', '')
                sha = issue.get('commit_sha')

            finding = NormalizedFinding(
                finding_id=f"static_{idx}",
                source="static",
                severity=severity,
                category=category,
                file_path=file_path,
                line_number=line,
                commit_sha=sha,
                description=desc,
                evidence=snippet,
                recommendation=rec
            )
            normalized.append(finding)
        
        logger.info(f"   Normalized {len(normalized)} static findings")
        return normalized
    
    def normalize_snyk_findings(self, snyk_analysis: Dict) -> List[NormalizedFinding]:
        """Normalize snyk analysis findings"""
        logger.info("🔄 Normalizing Snyk analysis findings...")
        
        normalized = []
        issues = snyk_analysis.get('issues', [])
        
        for idx, issue in enumerate(issues):
            finding = NormalizedFinding(
                finding_id=f"snyk_{idx}",
                source="snyk",
                severity=issue.get('severity', 'MEDIUM').upper(),
                category=issue.get('category', 'unknown'),
                file_path=issue.get('file_path'),
                line_number=issue.get('line_number'),
                description=issue.get('description', ''),
                evidence=f"Tool: Snyk SAST\nRule: {issue.get('category')}",
                recommendation="Fix the vulnerability as recommended by Snyk."
            )
            normalized.append(finding)
            
        logger.info(f"   Normalized {len(normalized)} Snyk findings")
        return normalized

    def normalize_dynamic_findings(self, dynamic_events: List[Dict]) -> List[NormalizedFinding]:
        """Normalize dynamic analysis findings to unified schema using LLM"""
        logger.info("🔄 Normalizing dynamic analysis findings...")
        
        # Group similar events to reduce noise
        grouped_events = self._group_similar_events(dynamic_events)
        logger.info(f"   Grouped {len(dynamic_events)} events into {len(grouped_events)} unique findings")
        
        normalized = []
        for idx, event in enumerate(grouped_events):
            finding = NormalizedFinding(
                finding_id=f"dynamic_{idx}",
                source="dynamic",
                severity=event.get('severity', 'MEDIUM'),
                category=event.get('category', 'unknown'),
                command=event.get('command'),
                process=event.get('process'),
                source_ip=event.get('source_ip'),
                dest_ip=event.get('dest_ip'),
                dest_port=event.get('dest_port'),
                description=event.get('description', ''),
                evidence=f"Command: {event.get('command', 'N/A')}\nConnection: {event.get('source_ip', '')} -> {event.get('dest_ip', '')}:{event.get('dest_port', '')}",
                recommendation=self._generate_dynamic_recommendation(event)
            )
            normalized.append(finding)
        
            normalized.append(finding)
        
        logger.info(f"   Normalized {len(normalized)} dynamic findings")
        return normalized
    
    def _group_similar_events(self, events: List[Dict]) -> List[Dict]:
        """Group similar dynamic events to avoid noise"""
        grouped = {}
        
        for event in events:
            # Group by: process + dest_ip + category
            key = (
                event.get('process', 'unknown'),
                event.get('dest_ip', 'unknown'),
                event.get('category', 'unknown')
            )
            
            if key not in grouped:
                grouped[key] = event.copy()
                grouped[key]['occurrence_count'] = 1
            else:
                grouped[key]['occurrence_count'] += 1
        
        return list(grouped.values())
    
    def _generate_dynamic_recommendation(self, event: Dict) -> str:
        """Generate recommendation based on dynamic event"""
        category = event.get('category', '')
        
        if category == 'reverse_shell':
            return "CRITICAL: Reverse shell detected. Immediately isolate the system, terminate the process, and investigate the source of compromise. Review all code changes and dependencies."
        elif category == 'data_exfiltration':
            return "CRITICAL: Data exfiltration detected. Block the destination IP/domain, audit all data access logs, and review code for malicious modifications."
        elif category == 'suspicious_network_access':
            return "HIGH: Suspicious network connection detected. Verify if this connection is expected. If not, investigate the code and dependencies for malicious activity."
        else:
            return "Review the connection and verify if it's expected behavior for this package."
    
    def compare_findings(
        self,
        static_findings: List[NormalizedFinding],
        dynamic_findings: List[NormalizedFinding],
        snyk_findings: Optional[List[NormalizedFinding]] = None
    ) -> VerificationResult:
        """
        Mult-way comparison of findings:
        1. Static vs Dynamic
        2. Static vs Snyk
        3. Snyk vs Dynamic
        
        If any pair matches on specific 'malicious' categories, flag as MALICIOUS.
        """
        logger.info("\n🔍 Verifying findings across all tools...")
        snyk_findings = snyk_findings or []
        
        result = VerificationResult()
        
        # 1. Compare Static vs Dynamic
        logger.info("   👉 Comparing Static <-> Dynamic...")
        matches_sd = self._match_findings_pair(static_findings, dynamic_findings, "Static", "Dynamic")
        result.static_dynamic_matches = matches_sd
        
        # 2. Compare Static vs Snyk
        if snyk_findings:
            logger.info("   👉 Comparing Static <-> Snyk...")
            matches_ss = self._match_findings_pair(static_findings, snyk_findings, "Static", "Snyk")
            result.static_snyk_matches = matches_ss
        
        # 3. Compare Snyk vs Dynamic
        if snyk_findings and dynamic_findings:
            logger.info("   👉 Comparing Snyk <-> Dynamic...")
            matches_snykd = self._match_findings_pair(snyk_findings, dynamic_findings, "Snyk", "Dynamic")
            result.snyk_dynamic_matches = matches_snykd
            
        # Collect all matched IDs to determine unmatched/suspicious
        matched_static_ids = set()
        matched_dynamic_ids = set()
        matched_snyk_ids = set()
        
        for s, d in result.static_dynamic_matches:
            matched_static_ids.add(s.finding_id)
            matched_dynamic_ids.add(d.finding_id)
            
        for s1, s2 in result.static_snyk_matches:
            matched_static_ids.add(s1.finding_id)
            matched_snyk_ids.add(s2.finding_id)
            
        for s, d in result.snyk_dynamic_matches:
            matched_snyk_ids.add(s.finding_id)
            matched_dynamic_ids.add(d.finding_id)
            
        # Populate suspicious lists (unmatched findings)
        # Note: Unmatched findings are 'suspicious' only if they are high severity, otherwise just 'unverified'
        # For simplicity, we list all unmatched as 'suspicious'/'unverified' for the report
        result.suspicious_static_only = [f for f in static_findings if f.finding_id not in matched_static_ids]
        result.suspicious_dynamic_only = [f for f in dynamic_findings if f.finding_id not in matched_dynamic_ids]
        result.suspicious_snyk_only = [f for f in snyk_findings if f.finding_id not in matched_snyk_ids]
        
        # Determine MALICIOUS verdict
        # Logic: If any pair confirms a vulnerability/malware/backdoor -> Mark as MALICIOUS
        all_matches = (
            result.static_dynamic_matches + 
            result.static_snyk_matches + 
            result.snyk_dynamic_matches
        )
        
        result.is_malicious = False
        malicious_categories = ['code_injection', 'remote_code_execution', 'command_injection', 'reverse_shell', 'data_exfiltration', 'backdoor', 'malware']
        
        malicious_categories = ['code_injection', 'remote_code_execution', 'command_injection', 'reverse_shell', 'data_exfiltration', 'backdoor', 'malware']
        
        logger.info("\n   ⚖️  Evaluating matches for MALICIOUS verdict...")
        for f1, f2 in all_matches:
            # Check if severity is High/Critical OR category is clearly malicious
            is_sev_high = f1.severity in ['HIGH', 'CRITICAL'] or f2.severity in ['HIGH', 'CRITICAL']
            is_cat_mal = any(cat in f1.category.lower() or cat in f2.category.lower() for cat in malicious_categories)
            
            if is_sev_high or is_cat_mal:
                result.is_malicious = True
                result.malicious_confidence = 1.0
                logger.warning(f"      🚨 MALICIOUS CONFIRMED by match: {f1.category} ({f1.source}) <-> {f2.category} ({f2.source})")
                break
        
        if not result.is_malicious:
             logger.info("      ✅ No confirmed malicious pairs found.")

        return result

    def _match_findings_pair(
        self, 
        findings_a: List[NormalizedFinding], 
        findings_b: List[NormalizedFinding],
        name_a: str,
        name_b: str
    ) -> List[Tuple[NormalizedFinding, NormalizedFinding]]:
        """Match two lists of findings using LLM"""
        # Quick exit if empty
        if not findings_a or not findings_b:
            return []
            
        matches = []
        try:
            # Prepare prompts
            summary_a = self._prepare_findings_for_llm(findings_a, name_a)
            summary_b = self._prepare_findings_for_llm(findings_b, name_b)
            
            system_prompt = prompts.CORRELATION_SYSTEM_PROMPT.format(name_a=name_a, name_b=name_b)
            user_prompt = prompts.CORRELATION_USER_PROMPT_TEMPLATE.format(
                name_a=name_a, 
                summary_a=summary_a, 
                name_b=name_b, 
                summary_b=summary_b
            )

            response = self.llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            data = self._parse_llm_matching_response(response.content)
            
            for match in data.get('matches', []):
                 f_a = next((f for f in findings_a if f.finding_id == match.get('id_a')), None)
                 f_b = next((f for f in findings_b if f.finding_id == match.get('id_b')), None)
                 
                 if f_a and f_b:
                     f_a.matched_finding_ids.append(f_b.finding_id)
                     f_b.matched_finding_ids.append(f_a.finding_id)
                     f_a.verification_status = "CONFIRMED"
                     f_b.verification_status = "CONFIRMED"
                     matches.append((f_a, f_b))
                     logger.info(f"      🔗 Match found: {f_a.category} <-> {f_b.category}")

        except Exception as e:
            logger.error(f"      ⚠️  Matching failed between {name_a} and {name_b}: {e}")
            
        return matches

    def _prepare_findings_for_llm(self, findings: List[NormalizedFinding], source_name: str) -> str:
        """Prepare findings summary for LLM"""
        lines = []
        for finding in findings[:20]:  # Limit to prevent token overflow
            lines.append(f"ID: {finding.finding_id}")
            lines.append(f"  Category: {finding.category}")
            lines.append(f"  Severity: {finding.severity}")
            if finding.file_path:
                lines.append(f"  Location: {finding.file_path}:{finding.line_number or '?'}")
            if finding.command:
                lines.append(f"  Command: {finding.command[:100]}")
            if finding.dest_ip:
                lines.append(f"  Network: {finding.dest_ip}:{finding.dest_port}")
            lines.append(f"  Description: {finding.description[:150]}")
            lines.append("")
        
        if len(findings) > 20:
            lines.append(f"... and {len(findings) - 20} more findings")
        
        return '\n'.join(lines)
    
    def _parse_llm_matching_response(self, response: str) -> Dict:
        """Parse LLM response for matches"""
        # Try to extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        return {'matches': []}
    
    def generate_comprehensive_report(
        self,
        result: VerificationResult,
        static_analysis: Dict,
        dynamic_analysis_path: str,
        snyk_analysis: Optional[Dict] = None
    ) -> str:
        """Generate comprehensive verification report using LLM"""
        logger.info("\n📝 Generating comprehensive report...")
        
        # Prepare data for LLM
        confirmed_count = (
            len(result.static_dynamic_matches) + 
            len(result.static_snyk_matches) + 
            len(result.snyk_dynamic_matches)
        )
        
        summary_text = f"MALICIOUS DETECTED: {result.is_malicious}" if result.is_malicious else "No definitive malicious behavior confirmed."
        
        prompt = prompts.REPORT_USER_PROMPT_TEMPLATE.format(
            summary_text=summary_text,
            match_count_sd=len(result.static_dynamic_matches),
            match_count_ss=len(result.static_snyk_matches),
            match_count_snykd=len(result.snyk_dynamic_matches),
            unmatched_static=len(result.suspicious_static_only),
            unmatched_dynamic=len(result.suspicious_dynamic_only),
            unmatched_snyk=len(result.suspicious_snyk_only),
            matches_sd_text=self._format_matches(result.static_dynamic_matches, "Static", "Dynamic"),
            matches_ss_text=self._format_matches(result.static_snyk_matches, "Static", "Snyk"),
            matches_snykd_text=self._format_matches(result.snyk_dynamic_matches, "Snyk", "Dynamic")
        )
        
        try:
            response = self.llm.invoke([
                SystemMessage(content=prompts.REPORT_SYSTEM_PROMPT),
                HumanMessage(content=prompt)
            ])
            
            response = self.llm.invoke([
                SystemMessage(content=prompts.REPORT_SYSTEM_PROMPT),
                HumanMessage(content=prompt)
            ])
            
            result.llm_analysis = response.content
            logger.info("✅ LLM analysis complete")
            
        except Exception as e:
            logger.error(f"⚠️  LLM report generation failed: {e}")
            result.llm_analysis = "LLM analysis unavailable."
        
        # Generate full report text
        report_lines = [
            "=" * 100,
            "VERIFICATION REPORT - MULTI-TOOL ANALYSIS",
            "=" * 100,
            f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Repository: {static_analysis.get('repository', 'N/A')}",
            f"Verdict: {'🚨 MALICIOUS' if result.is_malicious else '✅ CLEAN / UNCONFIRMED'}",
            f"\n{'=' * 100}",
            "EXECUTIVE SUMMARY",
            "=" * 100,
            result.llm_analysis,
            f"\n{'=' * 100}",
            "DETAILED MATCHES",
            "=" * 100,
        ]
        
        if result.static_dynamic_matches:
            report_lines.append("\n👉 STATIC <-> DYNAMIC MATCHES")
            report_lines.append(self._format_matches_detail(result.static_dynamic_matches))
            
        if result.static_snyk_matches:
            report_lines.append("\n👉 STATIC <-> SNYK MATCHES")
            report_lines.append(self._format_matches_detail(result.static_snyk_matches))
            
        if result.snyk_dynamic_matches:
            report_lines.append("\n👉 SNYK <-> DYNAMIC MATCHES")
            report_lines.append(self._format_matches_detail(result.snyk_dynamic_matches))
            
        report_lines.extend([
            f"\n{'=' * 100}",
            "UNVERIFIED / SUSPICIOUS FINDINGS",
            "=" * 100,
        ])
        
        if result.suspicious_static_only:
             report_lines.append(f"\n[Static Only] ({len(result.suspicious_static_only)} findings)")
             report_lines.append(self._format_findings_list(result.suspicious_static_only))
             
        if result.suspicious_dynamic_only:
             report_lines.append(f"\n[Dynamic Only] ({len(result.suspicious_dynamic_only)} findings)")
             report_lines.append(self._format_findings_list(result.suspicious_dynamic_only))

        if result.suspicious_snyk_only:
             report_lines.append(f"\n[Snyk Only] ({len(result.suspicious_snyk_only)} findings)")
             report_lines.append(self._format_findings_list(result.suspicious_snyk_only))

        result.comprehensive_report = '\n'.join(report_lines)
        return result.comprehensive_report
    
    def _format_matches(self, matches: List[Tuple[NormalizedFinding, NormalizedFinding]], name_a: str, name_b: str) -> str:
        if not matches:
            return ""
        lines = [f"--- {name_a} vs {name_b} ---"]
        for f1, f2 in matches[:5]:
            lines.append(f"- {f1.category} ({f1.severity}) matches {f2.category} ({f2.severity})")
            lines.append(f"  {name_a}: {f1.description[:80]}...")
            lines.append(f"  {name_b}: {f2.description[:80]}...")
        return "\n".join(lines)

    def _format_matches_detail(self, matches: List[Tuple[NormalizedFinding, NormalizedFinding]]) -> str:
        lines = []
        for idx, (f1, f2) in enumerate(matches, 1):
            lines.append(f"\n[{idx}] MATCH: {f1.category}")
            lines.append(f"   Source A ({f1.source}): {f1.description}")
            lines.append(f"   Source B ({f2.source}): {f2.description}")
            lines.append(f"   Severity: {f1.severity} / {f2.severity}")
        return "\n".join(lines)

    def _format_findings_list(self, findings: List[NormalizedFinding]) -> str:
        """Format findings list for report"""
        lines = []
        for idx, finding in enumerate(findings[:10], 1):
            lines.append(f"{idx}. {finding.severity} - {finding.category}")
            lines.append(f"   {finding.description[:200]}")
            if finding.file_path:
                lines.append(f"   File: {finding.file_path}")
        if len(findings) > 10:
            lines.append(f"... and {len(findings) - 10} more findings")
        return '\n'.join(lines)


def verify_analysis(
    static_analysis_json: str,
    dynamic_analysis_log: Optional[str] = None,
    output_dir: str = ".",
    snyk_analysis_json: Optional[str] = None
) -> VerificationResult:
    """
    Main verification function
    """
    logger.info("\n" + "=" * 100)
    logger.info("🔍 VERIFICATION ANALYSIS - MULTI-TOOL COMPARISON")
    logger.info("=" * 100)
    
    # Load static analysis
    
    # Load static analysis
    print("=" * 100)
    
    # Load static analysis
    logger.info(f"\n📂 Loading static analysis: {static_analysis_json}")
    with open(static_analysis_json, 'r') as f:
        static_analysis = json.load(f)
    
    # Parse dynamic analysis if provided
    dynamic_events = []
    if dynamic_analysis_log and os.path.exists(dynamic_analysis_log):
        logger.info(f"📂 Loading dynamic analysis: {dynamic_analysis_log}")
        parser = DynamicAnalysisParser()
        dynamic_events = parser.parse_package_hunter_log(dynamic_analysis_log)
    else:
        logger.info("ℹ️  No dynamic analysis log provided or file not found. Skipping dynamic analysis integration.")
    
    # Load Snyk analysis if provided
    snyk_analysis = {}
    if snyk_analysis_json and os.path.exists(snyk_analysis_json):
        logger.info(f"📂 Loading Snyk analysis: {snyk_analysis_json}")
        with open(snyk_analysis_json, 'r') as f:
             snyk_analysis = json.load(f)
    
    # Initialize verifier
    verifier = VerificationAnalyzer()
    
    # Normalize findings
    static_findings = verifier.normalize_static_findings(static_analysis)
    dynamic_findings = verifier.normalize_dynamic_findings(dynamic_events)
    snyk_findings = verifier.normalize_snyk_findings(snyk_analysis) if snyk_analysis else []
    
    # Compare findings
    result = verifier.compare_findings(static_findings, dynamic_findings, snyk_findings)
    
    # Generate comprehensive report
    report = verifier.generate_comprehensive_report(result, static_analysis, dynamic_analysis_log or "N/A", snyk_analysis)
    
    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(output_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # Save reports
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = os.path.join(reports_dir, f"verification_report_{timestamp}.md")
    with open(report_file, 'w') as f:
        f.write(report)
    
    # Save reports
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = os.path.join(reports_dir, f"verification_report_{timestamp}.md")
    with open(report_file, 'w') as f:
        f.write(report)
    
    logger.info(f"\n✅ Verification complete!")
    logger.info(f"📄 Report saved to: {report_file}")
    
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        logger.error("Usage: python verification.py <static.json> <dynamic.log> [output_dir] [snyk.json]")
        sys.exit(1)
    
    static_json = sys.argv[1]
    dynamic_log = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "."
    snyk_json = sys.argv[4] if len(sys.argv) > 4 else None
    
    result = verify_analysis(static_json, dynamic_log, output_dir, snyk_json)
    
    logger.info(f"\n{'=' * 100}")
    logger.info("VERIFICATION SUMMARY")
    logger.info("=" * 100)
    logger.info(f"Verdict: {'🚨 MALICIOUS' if result.is_malicious else '✅ CLEAN/UNCONFIRMED'}")

