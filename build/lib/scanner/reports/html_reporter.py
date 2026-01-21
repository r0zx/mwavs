"""HTML report generator."""

import html
from typing import Dict, Any, List
from datetime import datetime

from .base_reporter import BaseReporter


class HTMLReporter(BaseReporter):
    """Generate HTML format reports."""
    
    # Color scheme for severities
    SEVERITY_COLORS = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#17a2b8',
        'info': '#6c757d',
    }
    
    SEVERITY_BG_COLORS = {
        'critical': '#f8d7da',
        'high': '#ffe5d0',
        'medium': '#fff3cd',
        'low': '#d1ecf1',
        'info': '#e2e3e5',
    }
    
    def generate(self, data: Dict[str, Any]) -> str:
        """
        Generate HTML report.
        
        Args:
            data: Scan results data
            
        Returns:
            HTML formatted string
        """
        scan_info = data.get('scan_info', {})
        summary = data.get('summary', {})
        findings = data.get('findings', [])
        errors = data.get('errors', [])
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MWAVS Scan Report - {html.escape(scan_info.get('target', 'Unknown'))}</title>
    <style>
        {self._get_styles()}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header(scan_info)}
        {self._generate_summary(summary)}
        {self._generate_findings_section(findings)}
        {self._generate_errors_section(errors)}
        {self._generate_footer()}
    </div>
    <script>
        {self._get_scripts()}
    </script>
</body>
</html>"""
        
        return html_content
    
    def _get_styles(self) -> str:
        """Get CSS styles for the report."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 
                         'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header .target {
            font-size: 14px;
            opacity: 0.9;
            word-break: break-all;
        }
        
        .header .meta {
            display: flex;
            gap: 20px;
            margin-top: 15px;
            font-size: 13px;
            opacity: 0.8;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            border-left: 4px solid;
        }
        
        .summary-card.critical { border-left-color: #dc3545; }
        .summary-card.high { border-left-color: #fd7e14; }
        .summary-card.medium { border-left-color: #ffc107; }
        .summary-card.low { border-left-color: #17a2b8; }
        .summary-card.info { border-left-color: #6c757d; }
        
        .summary-card .count {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .summary-card .label {
            font-size: 14px;
            text-transform: uppercase;
            color: #666;
        }
        
        .section {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .section h2 {
            font-size: 20px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        
        .finding {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
        }
        
        .finding-header {
            padding: 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s;
        }
        
        .finding-header:hover {
            background: #f8f9fa;
        }
        
        .finding-title {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-badge.critical { background: #f8d7da; color: #721c24; }
        .severity-badge.high { background: #ffe5d0; color: #856404; }
        .severity-badge.medium { background: #fff3cd; color: #856404; }
        .severity-badge.low { background: #d1ecf1; color: #0c5460; }
        .severity-badge.info { background: #e2e3e5; color: #383d41; }
        
        .finding-details {
            padding: 0 15px 15px 15px;
            display: none;
            border-top: 1px solid #eee;
        }
        
        .finding.expanded .finding-details {
            display: block;
        }
        
        .detail-group {
            margin-bottom: 15px;
        }
        
        .detail-label {
            font-weight: bold;
            color: #555;
            margin-bottom: 5px;
            font-size: 13px;
        }
        
        .detail-value {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 13px;
            white-space: pre-wrap;
            word-break: break-all;
            overflow-x: auto;
        }
        
        .confidence-bar {
            background: #e9ecef;
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
            width: 100px;
        }
        
        .confidence-fill {
            height: 100%;
            background: #28a745;
            border-radius: 4px;
        }
        
        .toggle-icon {
            font-size: 20px;
            transition: transform 0.2s;
        }
        
        .finding.expanded .toggle-icon {
            transform: rotate(180deg);
        }
        
        .errors-list {
            list-style: none;
        }
        
        .errors-list li {
            padding: 10px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            margin-bottom: 10px;
            border-radius: 0 5px 5px 0;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 13px;
        }
        
        .no-findings {
            text-align: center;
            padding: 40px;
            color: #28a745;
        }
        
        .no-findings .icon {
            font-size: 48px;
            margin-bottom: 10px;
        }
        
        @media (max-width: 768px) {
            .header .meta {
                flex-direction: column;
                gap: 5px;
            }
            
            .summary-cards {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        """
    
    def _get_scripts(self) -> str:
        """Get JavaScript for interactivity."""
        return """
        document.querySelectorAll('.finding-header').forEach(header => {
            header.addEventListener('click', () => {
                const finding = header.parentElement;
                finding.classList.toggle('expanded');
            });
        });
        
        // Expand all critical and high findings by default
        document.querySelectorAll('.finding.critical, .finding.high').forEach(finding => {
            finding.classList.add('expanded');
        });
        """
    
    def _generate_header(self, scan_info: Dict[str, Any]) -> str:
        """Generate header section."""
        target = html.escape(str(scan_info.get('target', 'Unknown')))
        scan_time = scan_info.get('scan_time', 'Unknown')
        duration = scan_info.get('duration', 0)
        plugins = ', '.join(scan_info.get('plugins_run', []))
        
        return f"""
        <div class="header">
            <h1>🔍 MWAVS Security Scan Report</h1>
            <div class="target">Target: {target}</div>
            <div class="meta">
                <span>📅 {scan_time}</span>
                <span>⏱️ Duration: {duration:.2f}s</span>
                <span>🔌 Plugins: {html.escape(plugins)}</span>
            </div>
        </div>
        """
    
    def _generate_summary(self, summary: Dict[str, Any]) -> str:
        """Generate summary cards."""
        cards = []
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = summary.get(severity, 0)
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}
            
            cards.append(f"""
            <div class="summary-card {severity}">
                <div class="count">{count}</div>
                <div class="label">{emoji.get(severity, '')} {severity}</div>
            </div>
            """)
        
        return f"""
        <div class="summary-cards">
            {''.join(cards)}
        </div>
        """
    
    def _generate_findings_section(self, findings: List[Dict[str, Any]]) -> str:
        """Generate findings section."""
        if not findings:
            return """
            <div class="section">
                <h2>📋 Findings</h2>
                <div class="no-findings">
                    <div class="icon">✅</div>
                    <div>No vulnerabilities detected</div>
                </div>
            </div>
            """
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings, 
            key=lambda x: severity_order.get(x.get('severity', 'info'), 5)
        )
        
        finding_html = []
        for i, finding in enumerate(sorted_findings):
            finding_html.append(self._generate_finding(finding, i))
        
        return f"""
        <div class="section">
            <h2>📋 Findings ({len(findings)})</h2>
            {''.join(finding_html)}
        </div>
        """
    
    def _generate_finding(self, finding: Dict[str, Any], index: int) -> str:
        """Generate HTML for a single finding."""
        severity = finding.get('severity', 'info')
        vuln_type = html.escape(str(finding.get('vulnerability_type', 'Unknown')))
        url = html.escape(str(finding.get('url', '')))
        confidence = finding.get('confidence', 0)
        parameter = html.escape(str(finding.get('parameter', 'N/A')))
        payload = html.escape(str(finding.get('payload', 'N/A')))
        evidence = html.escape(str(finding.get('evidence', 'N/A')))
        description = html.escape(str(finding.get('description', 'N/A')))
        remediation = html.escape(str(finding.get('remediation', 'N/A')))
        plugin = html.escape(str(finding.get('plugin_name', 'Unknown')))
        
        return f"""
        <div class="finding {severity}">
            <div class="finding-header">
                <div class="finding-title">
                    <span class="severity-badge {severity}">{severity}</span>
                    <span><strong>{vuln_type}</strong></span>
                </div>
                <div style="display: flex; align-items: center; gap: 15px;">
                    <div class="confidence-bar" title="Confidence: {confidence}%">
                        <div class="confidence-fill" style="width: {confidence}%"></div>
                    </div>
                    <span class="toggle-icon">▼</span>
                </div>
            </div>
            <div class="finding-details">
                <div class="detail-group">
                    <div class="detail-label">URL</div>
                    <div class="detail-value">{url}</div>
                </div>
                <div class="detail-group">
                    <div class="detail-label">Parameter</div>
                    <div class="detail-value">{parameter}</div>
                </div>
                <div class="detail-group">
                    <div class="detail-label">Payload</div>
                    <div class="detail-value">{payload}</div>
                </div>
                <div class="detail-group">
                    <div class="detail-label">Evidence</div>
                    <div class="detail-value">{evidence}</div>
                </div>
                <div class="detail-group">
                    <div class="detail-label">Description</div>
                    <div class="detail-value">{description}</div>
                </div>
                <div class="detail-group">
                    <div class="detail-label">Remediation</div>
                    <div class="detail-value">{remediation}</div>
                </div>
                <div class="detail-group">
                    <div class="detail-label">Plugin</div>
                    <div class="detail-value">{plugin}</div>
                </div>
            </div>
        </div>
        """
    
    def _generate_errors_section(self, errors: List[str]) -> str:
        """Generate errors section."""
        if not errors:
            return ""
        
        error_items = '\n'.join(
            f'<li>{html.escape(str(error))}</li>' for error in errors
        )
        
        return f"""
        <div class="section">
            <h2>⚠️ Errors ({len(errors)})</h2>
            <ul class="errors-list">
                {error_items}
            </ul>
        </div>
        """
    
    def _generate_footer(self) -> str:
        """Generate footer section."""
        return f"""
        <div class="footer">
            Generated by MWAVS (Modular Web Application Vulnerability Scanner) v1.0.0<br>
            Report generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        </div>
        """