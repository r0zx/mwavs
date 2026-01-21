"""Plain text report generator."""

from typing import Dict, Any, List
from datetime import datetime

from .base_reporter import BaseReporter


class TxtReporter(BaseReporter):
    """Generate plain text format reports."""
    
    def __init__(self, width: int = 80):
        self.width = width
    
    def generate(self, data: Dict[str, Any]) -> str:
        """
        Generate plain text report.
        
        Args:
            data: Scan results data
            
        Returns:
            Plain text formatted string
        """
        lines = []
        
        # Header
        lines.append("=" * self.width)
        lines.append(self._center("MWAVS SECURITY SCAN REPORT"))
        lines.append(self._center("Modular Web Application Vulnerability Scanner"))
        lines.append("=" * self.width)
        lines.append("")
        
        # Scan Info
        scan_info = data.get('scan_info', {})
        lines.append(self._section_header("SCAN INFORMATION"))
        lines.append(f"Target:     {scan_info.get('target', 'Unknown')}")
        lines.append(f"Scan Time:  {scan_info.get('scan_time', 'Unknown')}")
        lines.append(f"Duration:   {scan_info.get('duration', 0):.2f} seconds")
        lines.append(f"Plugins:    {', '.join(scan_info.get('plugins_run', []))}")
        lines.append("")
        
        # Summary
        summary = data.get('summary', {})
        lines.append(self._section_header("SUMMARY"))
        lines.append(f"Total Findings: {scan_info.get('total_findings', 0)}")
        lines.append("")
        lines.append("  Severity Breakdown:")
        lines.append(f"    CRITICAL: {summary.get('critical', 0)}")
        lines.append(f"    HIGH:     {summary.get('high', 0)}")
        lines.append(f"    MEDIUM:   {summary.get('medium', 0)}")
        lines.append(f"    LOW:      {summary.get('low', 0)}")
        lines.append(f"    INFO:     {summary.get('info', 0)}")
        lines.append("")
        
        # Findings
        findings = data.get('findings', [])
        lines.append(self._section_header(f"FINDINGS ({len(findings)})"))
        
        if not findings:
            lines.append("  No vulnerabilities detected.")
            lines.append("")
        else:
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_findings = sorted(
                findings, 
                key=lambda x: severity_order.get(x.get('severity', 'info'), 5)
            )
            
            for i, finding in enumerate(sorted_findings, 1):
                lines.extend(self._format_finding(finding, i))
        
        # Errors
        errors = data.get('errors', [])
        if errors:
            lines.append(self._section_header(f"ERRORS ({len(errors)})"))
            for error in errors:
                lines.append(f"  - {error}")
            lines.append("")
        
        # Footer
        lines.append("=" * self.width)
        lines.append(self._center(f"Report generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"))
        lines.append(self._center("MWAVS v1.0.0"))
        lines.append("=" * self.width)
        
        return "\n".join(lines)
    
    def _center(self, text: str) -> str:
        """Center text within width."""
        return text.center(self.width)
    
    def _section_header(self, title: str) -> str:
        """Create section header."""
        return f"\n{'─' * self.width}\n {title}\n{'─' * self.width}"
    
    def _format_finding(self, finding: Dict[str, Any], index: int) -> List[str]:
        """Format a single finding."""
        lines = []
        
        severity = finding.get('severity', 'info').upper()
        vuln_type = finding.get('vulnerability_type', 'Unknown')
        
        lines.append(f"\n  [{index}] [{severity}] {vuln_type}")
        lines.append(f"  {'─' * (self.width - 4)}")
        
        fields = [
            ('URL', finding.get('url')),
            ('Parameter', finding.get('parameter')),
            ('Confidence', f"{finding.get('confidence', 0)}%"),
            ('Plugin', finding.get('plugin_name')),
        ]
        
        for label, value in fields:
            if value:
                lines.append(f"  {label}: {value}")
        
        # Payload
        payload = finding.get('payload')
        if payload:
            lines.append(f"  Payload:")
            for line in str(payload)[:200].split('\n'):
                lines.append(f"    {line}")
        
        # Evidence
        evidence = finding.get('evidence')
        if evidence:
            lines.append(f"  Evidence:")
            for line in str(evidence)[:500].split('\n'):
                lines.append(f"    {line}")
        
        # Description
        description = finding.get('description')
        if description:
            lines.append(f"  Description:")
            # Word wrap
            words = str(description).split()
            current_line = "    "
            for word in words:
                if len(current_line) + len(word) + 1 > self.width - 4:
                    lines.append(current_line)
                    current_line = "    " + word
                else:
                    current_line += " " + word if current_line.strip() else "    " + word
            if current_line.strip():
                lines.append(current_line)
        
        # Remediation
        remediation = finding.get('remediation')
        if remediation:
            lines.append(f"  Remediation:")
            words = str(remediation).split()
            current_line = "    "
            for word in words:
                if len(current_line) + len(word) + 1 > self.width - 4:
                    lines.append(current_line)
                    current_line = "    " + word
                else:
                    current_line += " " + word if current_line.strip() else "    " + word
            if current_line.strip():
                lines.append(current_line)
        
        lines.append("")
        return lines