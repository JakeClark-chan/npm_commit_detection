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
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

load_dotenv()


@dataclass
class NormalizedFinding:
    """Unified schema for both static and dynamic analysis findings"""
    finding_id: str
    source: str  # "static" or "dynamic"
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # network_access, command_injection, data_exfiltration, etc.
    
    # Location information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    commit_sha: Optional[str] = None
    
    # Network information (for dynamic analysis)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    
    # Command information
    command: Optional[str] = None
    process: Optional[str] = None
    
    # Description and evidence
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    
    # Verification status
    verification_status: str = "UNVERIFIED"  # CONFIRMED, SUSPICIOUS, UNVERIFIED
    matched_finding_id: Optional[str] = None


@dataclass
class VerificationResult:
    """Result of comparing static and dynamic analysis"""
    confirmed_findings: List[Tuple[NormalizedFinding, NormalizedFinding]] = field(default_factory=list)
    suspicious_static_only: List[NormalizedFinding] = field(default_factory=list)
    suspicious_dynamic_only: List[NormalizedFinding] = field(default_factory=list)
    llm_analysis: str = ""
    comprehensive_report: str = ""


class DynamicAnalysisParser:
    """Parse Package Hunter dynamic analysis logs"""
    
    def __init__(self):
        self.findings = []
    
    def parse_package_hunter_log(self, log_path: str) -> List[Dict]:
        """Parse Package Hunter JSON log"""
        print(f"📄 Parsing dynamic analysis log: {log_path}")
        
        with open(log_path, 'r') as f:
            content = f.read().strip()
            # Remove trailing characters that might not be part of JSON (like shell prompt %)
            # Find the last closing brace
            last_brace = content.rfind('}')
            if last_brace != -1:
                content = content[:last_brace + 1]
            data = json.loads(content)
        
        if not isinstance(data, dict) or 'result' not in data:
            raise ValueError("Invalid Package Hunter log format")
        
        results = data['result']
        print(f"   Found {len(results)} dynamic analysis events")
        
        parsed_findings = []
        for idx, event in enumerate(results):
            finding = self._parse_event(event, idx)
            if finding:
                parsed_findings.append(finding)
        
        return parsed_findings
    
    def _parse_event(self, event: Dict, idx: int) -> Optional[Dict]:
        """Parse a single Package Hunter event"""
        output_fields = event.get('output_fields', {})
        
        # Extract command
        command = output_fields.get('proc.cmdline', '')
        
        # Extract network connection
        fd_name = output_fields.get('fd.name', '')
        source_ip, dest_ip, dest_port = self._parse_connection(fd_name)
        
        # Determine severity and category
        severity, category = self._classify_event(command, dest_ip, dest_port)
        
        return {
            'finding_id': f"dynamic_{idx}",
            'source': 'dynamic',
            'severity': severity,
            'category': category,
            'rule': event.get('rule', ''),
            'priority': event.get('priority', ''),
            'command': command,
            'process': self._extract_process_name(command),
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'dest_port': dest_port,
            'container_name': output_fields.get('container.name', ''),
            'timestamp': event.get('time', {}),
            'description': event.get('output', ''),
        }
    
    def _parse_connection(self, fd_name: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Parse connection string like '172.17.0.2:33906->54.77.139.23:443'"""
        if not fd_name or '->' not in fd_name:
            return None, None, None
        
        try:
            source, dest = fd_name.split('->')
            source_ip = source.split(':')[0] if ':' in source else None
            
            if ':' in dest:
                dest_parts = dest.split(':')
                dest_ip = dest_parts[0]
                dest_port = int(dest_parts[1]) if dest_parts[1].isdigit() else None
            else:
                dest_ip = dest
                dest_port = None
            
            return source_ip, dest_ip, dest_port
        except Exception:
            return None, None, None
    
    def _extract_process_name(self, command: str) -> Optional[str]:
        """Extract process name from command"""
        if not command:
            return None
        
        # Extract first word/executable
        parts = command.split()
        if parts:
            return parts[0]
        return None
    
    def _classify_event(self, command: str, dest_ip: str, dest_port: int) -> Tuple[str, str]:
        """Classify event severity and category"""
        command_lower = command.lower() if command else ''
        
        # Reverse shell detection
        if any(keyword in command_lower for keyword in ['socket.socket', 'subprocess.call', '/bin/sh', 'bash -i']):
            return 'CRITICAL', 'reverse_shell'
        
        # Data exfiltration
        if 'exfil' in command_lower or 'malware' in command_lower:
            return 'CRITICAL', 'data_exfiltration'
        
        # Suspicious network access
        if dest_ip and dest_port:
            # Common suspicious ports
            suspicious_ports = [22, 23, 3389, 4444, 5555, 8080, 8888, 9999]
            if dest_port in suspicious_ports or dest_port > 20000:
                return 'HIGH', 'suspicious_network_access'
        
        return 'MEDIUM', 'network_access'


class VerificationAnalyzer:
    """Verify and compare static vs dynamic analysis using LLM"""
    
    def __init__(self, verification_model: Optional[str] = None):
        model_name = verification_model or os.getenv("LLM_VERIFICATION_MODEL", "gpt-4o-mini")
        temp = float(os.getenv("LLM_VERIFICATION_TEMPERATURE", "1"))
        print(f"🤖 Initializing verification LLM: {model_name} (temperature={temp})")
        
        self.llm = ChatOpenAI(
            model=model_name,
            temperature=temp,
            api_key=os.getenv("OPENAI_API_KEY")
        )
    
    def normalize_static_findings(self, static_analysis: Dict) -> List[NormalizedFinding]:
        """Normalize static analysis findings to unified schema"""
        print("🔄 Normalizing static analysis findings...")
        
        normalized = []
        issues = static_analysis.get('static_analysis', {}).get('issues', [])
        
        for idx, issue in enumerate(issues):
            finding = NormalizedFinding(
                finding_id=f"static_{idx}",
                source="static",
                severity=issue.get('severity', 'MEDIUM'),
                category=issue.get('category', 'unknown'),
                file_path=issue.get('file_path'),
                line_number=issue.get('line_number'),
                commit_sha=issue.get('commit_sha'),
                description=issue.get('description', ''),
                evidence=issue.get('code_snippet', ''),
                recommendation=issue.get('recommendation', '')
            )
            normalized.append(finding)
        
        print(f"   Normalized {len(normalized)} static findings")
        return normalized
    
    def normalize_dynamic_findings(self, dynamic_events: List[Dict]) -> List[NormalizedFinding]:
        """Normalize dynamic analysis findings to unified schema using LLM"""
        print("🔄 Normalizing dynamic analysis findings...")
        
        # Group similar events to reduce noise
        grouped_events = self._group_similar_events(dynamic_events)
        print(f"   Grouped {len(dynamic_events)} events into {len(grouped_events)} unique findings")
        
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
        
        print(f"   Normalized {len(normalized)} dynamic findings")
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
        dynamic_findings: List[NormalizedFinding]
    ) -> VerificationResult:
        """Compare static and dynamic findings using LLM intelligence"""
        print("\n🔍 Comparing static and dynamic analysis findings...")
        
        result = VerificationResult()
        
        # Use LLM to intelligently match findings
        matches = self._llm_match_findings(static_findings, dynamic_findings)
        
        # Process matches
        matched_static_ids = set()
        matched_dynamic_ids = set()
        
        for static_finding, dynamic_finding, confidence in matches:
            if confidence > 0.7:  # High confidence match
                static_finding.verification_status = "CONFIRMED"
                static_finding.matched_finding_id = dynamic_finding.finding_id
                dynamic_finding.verification_status = "CONFIRMED"
                dynamic_finding.matched_finding_id = static_finding.finding_id
                
                result.confirmed_findings.append((static_finding, dynamic_finding))
                matched_static_ids.add(static_finding.finding_id)
                matched_dynamic_ids.add(dynamic_finding.finding_id)
                print(f"   ✅ CONFIRMED: {static_finding.category} matched with {dynamic_finding.category}")
        
        # Mark unmatched as suspicious
        for finding in static_findings:
            if finding.finding_id not in matched_static_ids:
                finding.verification_status = "SUSPICIOUS"
                result.suspicious_static_only.append(finding)
                print(f"   ⚠️  SUSPICIOUS (static only): {finding.category}")
        
        for finding in dynamic_findings:
            if finding.finding_id not in matched_dynamic_ids:
                finding.verification_status = "SUSPICIOUS"
                result.suspicious_dynamic_only.append(finding)
                print(f"   ⚠️  SUSPICIOUS (dynamic only): {finding.category}")
        
        print(f"\n📊 Verification Summary:")
        print(f"   Confirmed findings: {len(result.confirmed_findings)}")
        print(f"   Suspicious (static only): {len(result.suspicious_static_only)}")
        print(f"   Suspicious (dynamic only): {len(result.suspicious_dynamic_only)}")
        
        return result
    
    def _llm_match_findings(
        self,
        static_findings: List[NormalizedFinding],
        dynamic_findings: List[NormalizedFinding]
    ) -> List[Tuple[NormalizedFinding, NormalizedFinding, float]]:
        """Use LLM to intelligently match static and dynamic findings"""
        matches = []
        
        # Prepare findings for LLM
        static_summary = self._prepare_findings_for_llm(static_findings, "static")
        dynamic_summary = self._prepare_findings_for_llm(dynamic_findings, "dynamic")

        system_prompt = """You are a security analyst expert at correlating static and dynamic analysis results.

Task: Match static findings with dynamic findings that represent the same security issue.
For each match, provide:
1. Static finding ID
2. Dynamic finding ID
3. Confidence score (0.0 to 1.0)
4. Brief explanation

Consider:
- Static findings predict vulnerabilities in code
- Dynamic findings show actual runtime behavior
- Match based on: category, file paths, command patterns, network destinations
- A static finding about network access to IP X should match dynamic connections to IP X
- A static reverse shell code pattern should match dynamic reverse shell execution

Output format (JSON):
{{
  "matches": [
    {{
      "static_id": "static_0",
      "dynamic_id": "dynamic_1",
      "confidence": 0.95,
      "explanation": "Both indicate reverse shell to 77.244.210.247"
    }}
  ]
}}

Provide only valid, high-confidence matches (>0.6).        

""" 
        
        user_prompt = f"""You are a security analyst comparing static code analysis with dynamic runtime analysis.

STATIC ANALYSIS FINDINGS:
{static_summary}

DYNAMIC ANALYSIS FINDINGS (Runtime Behavior):
{dynamic_summary}
"""
        
        try:
            response = self.llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            # Parse LLM response
            result = self._parse_llm_matching_response(response.content)
            
            # Convert to finding tuples
            for match in result.get('matches', []):
                static_finding = next((f for f in static_findings if f.finding_id == match['static_id']), None)
                dynamic_finding = next((f for f in dynamic_findings if f.finding_id == match['dynamic_id']), None)
                
                if static_finding and dynamic_finding:
                    matches.append((static_finding, dynamic_finding, match['confidence']))
                    print(f"   🔗 Match: {match['static_id']} <-> {match['dynamic_id']} (confidence: {match['confidence']:.2f})")
                    print(f"      {match['explanation']}")
        
        except Exception as e:
            print(f"   ⚠️  LLM matching failed: {e}")
            # Fallback to simple matching
            matches = self._simple_match_findings(static_findings, dynamic_findings)
        
        return matches
    
    def _prepare_findings_for_llm(self, findings: List[NormalizedFinding], source_type: str) -> str:
        """Prepare findings summary for LLM"""
        lines = []
        for finding in findings[:20]:  # Limit to prevent token overflow
            if source_type == "static":
                lines.append(f"ID: {finding.finding_id}")
                lines.append(f"  Category: {finding.category}")
                lines.append(f"  Severity: {finding.severity}")
                lines.append(f"  File: {finding.file_path}:{finding.line_number}")
                lines.append(f"  Description: {finding.description[:200]}")
                lines.append("")
            else:  # dynamic
                lines.append(f"ID: {finding.finding_id}")
                lines.append(f"  Category: {finding.category}")
                lines.append(f"  Severity: {finding.severity}")
                lines.append(f"  Process: {finding.process}")
                lines.append(f"  Command: {finding.command[:150] if finding.command else 'N/A'}")
                lines.append(f"  Network: {finding.dest_ip}:{finding.dest_port}")
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
    
    def _simple_match_findings(
        self,
        static_findings: List[NormalizedFinding],
        dynamic_findings: List[NormalizedFinding]
    ) -> List[Tuple[NormalizedFinding, NormalizedFinding, float]]:
        """Simple rule-based matching as fallback"""
        matches = []
        
        for static in static_findings:
            for dynamic in dynamic_findings:
                confidence = 0.0
                
                # Category match
                if static.category == dynamic.category:
                    confidence += 0.4
                
                # Check for IP addresses in static description matching dynamic dest_ip
                if dynamic.dest_ip and static.description:
                    if dynamic.dest_ip in static.description:
                        confidence += 0.5
                
                # Check for command patterns
                if dynamic.command and static.description:
                    if 'reverse shell' in static.description.lower() and 'socket' in dynamic.command.lower():
                        confidence += 0.3
                
                if confidence > 0.6:
                    matches.append((static, dynamic, confidence))
        
        return matches
    
    def generate_comprehensive_report(
        self,
        result: VerificationResult,
        static_analysis: Dict,
        dynamic_analysis_path: str
    ) -> str:
        """Generate comprehensive verification report using LLM"""
        print("\n📝 Generating comprehensive report...")
        
        # Prepare data for LLM
        summary = {
            'confirmed_count': len(result.confirmed_findings),
            'suspicious_static_count': len(result.suspicious_static_only),
            'suspicious_dynamic_count': len(result.suspicious_dynamic_only),
            'total_static': len(result.suspicious_static_only) + len(result.confirmed_findings),
            'total_dynamic': len(result.suspicious_dynamic_only) + len(result.confirmed_findings),
        }
        
        prompt = f"""You are a senior security analyst generating a comprehensive security report.

VERIFICATION RESULTS:
- Total static analysis findings: {summary['total_static']}
- Total dynamic analysis findings: {summary['total_dynamic']}
- CONFIRMED findings (both static and dynamic): {summary['confirmed_count']}
- SUSPICIOUS (static only, not seen at runtime): {summary['suspicious_static_count']}
- SUSPICIOUS (dynamic only, not predicted by static): {summary['suspicious_dynamic_count']}

CONFIRMED FINDINGS:
{self._format_confirmed_findings(result.confirmed_findings)}

SUSPICIOUS STATIC-ONLY FINDINGS:
{self._format_findings_list(result.suspicious_static_only)}

SUSPICIOUS DYNAMIC-ONLY FINDINGS:
{self._format_findings_list(result.suspicious_dynamic_only)}

Generate a comprehensive security report in Vietnamese and English with:
1. Executive Summary (Tóm tắt)
2. Risk Assessment (Đánh giá rủi ro)
3. Detailed Findings (Chi tiết phát hiện)
4. Remediation Recommendations (Khuyến nghị khắc phục)
5. Conclusion (Kết luận)

Focus on actionable insights and clear explanations.
"""
        
        try:
            response = self.llm.invoke([
                SystemMessage(content="You are a senior security analyst specializing in comprehensive security reporting."),
                HumanMessage(content=prompt)
            ])
            
            result.llm_analysis = response.content
            print("✅ LLM analysis complete")
            
        except Exception as e:
            print(f"⚠️  LLM report generation failed: {e}")
            result.llm_analysis = "LLM analysis unavailable."
        
        # Generate full report
        report_lines = [
            "=" * 100,
            "VERIFICATION REPORT - STATIC vs DYNAMIC ANALYSIS COMPARISON",
            "BÁO CÁO XÁC MINH - SO SÁNH PHÂN TÍCH TĨNH VÀ ĐỘNG",
            "=" * 100,
            f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Repository: {static_analysis.get('repository', 'N/A')}",
            f"Version: {static_analysis.get('version', 'N/A')}",
            f"\n{'=' * 100}",
            "VERIFICATION SUMMARY / TÓNG KẾT XÁC MINH",
            "=" * 100,
            f"\n✅ CONFIRMED Findings (Xác nhận): {summary['confirmed_count']}",
            f"   - Both static analysis and dynamic runtime behavior agree",
            f"   - High confidence security issues",
            f"\n⚠️  SUSPICIOUS Static-Only (Nghi ngờ - chỉ tĩnh): {summary['suspicious_static_count']}",
            f"   - Detected in code but not observed at runtime",
            f"   - May be false positives or conditional vulnerabilities",
            f"\n⚠️  SUSPICIOUS Dynamic-Only (Nghi ngờ - chỉ động): {summary['suspicious_dynamic_count']}",
            f"   - Observed at runtime but not predicted by static analysis",
            f"   - May indicate sophisticated evasion or analysis gaps",
            f"\n{'=' * 100}",
            "LLM SECURITY ANALYSIS / PHÂN TÍCH BẢO MẬT",
            "=" * 100,
            result.llm_analysis,
            f"\n{'=' * 100}",
            "DETAILED VERIFIED FINDINGS / CHI TIẾT CÁC PHÁT HIỆN ĐÃ XÁC MINH",
            "=" * 100,
        ]
        
        # Add confirmed findings details
        for idx, (static, dynamic) in enumerate(result.confirmed_findings, 1):
            report_lines.extend([
                f"\n[{idx}] ✅ CONFIRMED - {static.severity}",
                f"Category: {static.category}",
                f"",
                f"STATIC ANALYSIS:",
                f"  File: {static.file_path}:{static.line_number}",
                f"  Description: {static.description}",
                f"",
                f"DYNAMIC RUNTIME:",
                f"  Process: {dynamic.process}",
                f"  Connection: {dynamic.dest_ip}:{dynamic.dest_port}",
                f"  Command: {dynamic.command[:200] if dynamic.command else 'N/A'}",
                f"",
                f"RECOMMENDATION:",
                f"  {static.recommendation}",
                "=" * 80,
            ])
        
        # Add suspicious findings
        if result.suspicious_static_only:
            report_lines.extend([
                f"\n{'=' * 100}",
                "SUSPICIOUS STATIC-ONLY FINDINGS / PHÁT HIỆN NGHI NGỜ (CHỈ TĨNH)",
                "=" * 100,
            ])
            for idx, finding in enumerate(result.suspicious_static_only, 1):
                report_lines.extend([
                    f"\n[{idx}] ⚠️  {finding.severity} - {finding.category}",
                    f"  File: {finding.file_path}:{finding.line_number}",
                    f"  {finding.description[:300]}",
                    ""
                ])
        
        if result.suspicious_dynamic_only:
            report_lines.extend([
                f"\n{'=' * 100}",
                "SUSPICIOUS DYNAMIC-ONLY FINDINGS / PHÁT HIỆN NGHI NGỜ (CHỈ ĐỘNG)",
                "=" * 100,
            ])
            for idx, finding in enumerate(result.suspicious_dynamic_only, 1):
                report_lines.extend([
                    f"\n[{idx}] ⚠️  {finding.severity} - {finding.category}",
                    f"  Process: {finding.process}",
                    f"  Network: {finding.dest_ip}:{finding.dest_port}",
                    f"  Command: {finding.command[:200] if finding.command else 'N/A'}",
                    ""
                ])
        
        report_lines.extend([
            "=" * 100,
            "END OF VERIFICATION REPORT",
            "=" * 100,
        ])
        
        result.comprehensive_report = '\n'.join(report_lines)
        return result.comprehensive_report
    
    def _format_confirmed_findings(self, confirmed: List[Tuple[NormalizedFinding, NormalizedFinding]]) -> str:
        """Format confirmed findings for LLM"""
        lines = []
        for idx, (static, dynamic) in enumerate(confirmed[:10], 1):
            lines.append(f"{idx}. {static.severity} - {static.category}")
            lines.append(f"   Static: {static.file_path} - {static.description[:150]}")
            lines.append(f"   Dynamic: {dynamic.process} -> {dynamic.dest_ip}:{dynamic.dest_port}")
            lines.append("")
        if len(confirmed) > 10:
            lines.append(f"... and {len(confirmed) - 10} more confirmed findings")
        return '\n'.join(lines)
    
    def _format_findings_list(self, findings: List[NormalizedFinding]) -> str:
        """Format findings list for LLM"""
        lines = []
        for idx, finding in enumerate(findings[:10], 1):
            lines.append(f"{idx}. {finding.severity} - {finding.category}")
            if finding.source == "static":
                lines.append(f"   File: {finding.file_path}")
                lines.append(f"   {finding.description[:150]}")
            else:
                lines.append(f"   Process: {finding.process}")
                lines.append(f"   Network: {finding.dest_ip}:{finding.dest_port}")
            lines.append("")
        if len(findings) > 10:
            lines.append(f"... and {len(findings) - 10} more findings")
        return '\n'.join(lines)


def verify_analysis(
    static_analysis_json: str,
    dynamic_analysis_log: str,
    output_dir: str = "."
) -> VerificationResult:
    """
    Main verification function
    
    Args:
        static_analysis_json: Path to static analysis JSON output
        dynamic_analysis_log: Path to package-hunter log
        output_dir: Directory for output reports
    """
    print("\n" + "=" * 100)
    print("🔍 VERIFICATION ANALYSIS - COMPARING STATIC AND DYNAMIC RESULTS")
    print("=" * 100)
    
    # Load static analysis
    print(f"\n📂 Loading static analysis: {static_analysis_json}")
    with open(static_analysis_json, 'r') as f:
        static_analysis = json.load(f)
    
    # Parse dynamic analysis
    parser = DynamicAnalysisParser()
    dynamic_events = parser.parse_package_hunter_log(dynamic_analysis_log)
    
    # Initialize verifier
    verifier = VerificationAnalyzer()
    
    # Normalize findings
    static_findings = verifier.normalize_static_findings(static_analysis)
    dynamic_findings = verifier.normalize_dynamic_findings(dynamic_events)
    
    # Compare findings
    result = verifier.compare_findings(static_findings, dynamic_findings)
    
    # Generate comprehensive report
    report = verifier.generate_comprehensive_report(result, static_analysis, dynamic_analysis_log)
    
    # Calculate accuracy score
    total_static = len(static_findings)
    confirmed_count = len(result.confirmed_findings)
    accuracy_score = (confirmed_count / total_static * 100) if total_static > 0 else 0
    
    print(f"\n📊 Accuracy Score: {accuracy_score:.2f}% ({confirmed_count}/{total_static} static findings confirmed by runtime)")
    
    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(output_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # Save reports
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = os.path.join(reports_dir, f"verification_report_{timestamp}.txt")
    json_file = os.path.join(reports_dir, f"verification_report_{timestamp}.json")
    
    with open(report_file, 'w') as f:
        f.write(report)
    
    # Save JSON summary
    json_data = {
        'timestamp': datetime.now().isoformat(),
        'static_analysis_source': static_analysis_json,
        'dynamic_analysis_source': dynamic_analysis_log,
        'summary': {
            'confirmed_findings': len(result.confirmed_findings),
            'suspicious_static_only': len(result.suspicious_static_only),
            'suspicious_dynamic_only': len(result.suspicious_dynamic_only),
            'total_static_findings': len(static_findings),
            'total_dynamic_findings': len(dynamic_findings),
            'accuracy_score': round(accuracy_score, 2),
        },
        'confirmed_findings': [
            {
                'static': {
                    'id': s.finding_id,
                    'severity': s.severity,
                    'category': s.category,
                    'file': s.file_path,
                    'description': s.description
                },
                'dynamic': {
                    'id': d.finding_id,
                    'severity': d.severity,
                    'category': d.category,
                    'process': d.process,
                    'network': f"{d.dest_ip}:{d.dest_port}"
                }
            }
            for s, d in result.confirmed_findings
        ],
        'suspicious_static_only': [
            {
                'id': f.finding_id,
                'severity': f.severity,
                'category': f.category,
                'file': f.file_path,
                'description': f.description
            }
            for f in result.suspicious_static_only
        ],
        'suspicious_dynamic_only': [
            {
                'id': f.finding_id,
                'severity': f.severity,
                'category': f.category,
                'process': f.process,
                'network': f"{f.dest_ip}:{f.dest_port}"
            }
            for f in result.suspicious_dynamic_only
        ]
    }
    
    with open(json_file, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    print(f"\n✅ Verification complete!")
    print(f"📄 Report saved to: {report_file}")
    print(f"📊 JSON data saved to: {json_file}")
    
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python verification.py <static_analysis.json> <package-hunter-log.txt> [output_dir]")
        sys.exit(1)
    
    static_json = sys.argv[1]
    dynamic_log = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "."
    
    result = verify_analysis(static_json, dynamic_log, output_dir)
    
    print(f"\n{'=' * 100}")
    print("VERIFICATION SUMMARY")
    print("=" * 100)
    print(f"✅ Confirmed findings: {len(result.confirmed_findings)}")
    print(f"⚠️  Suspicious (static only): {len(result.suspicious_static_only)}")
    print(f"⚠️  Suspicious (dynamic only): {len(result.suspicious_dynamic_only)}")
    
    total_static = len([f for f in result.confirmed_findings]) + len(result.suspicious_static_only)
    confirmed = len(result.confirmed_findings)
    accuracy = (confirmed / total_static * 100) if total_static > 0 else 0
    print(f"\n📊 Accuracy Score: {accuracy:.2f}% ({confirmed}/{total_static} predictions confirmed)")
