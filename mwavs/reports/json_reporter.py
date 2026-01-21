"""JSON report generator."""

import json
from typing import Dict, Any
from datetime import datetime

from .base_reporter import BaseReporter


class JSONReporter(BaseReporter):
    """Generate JSON format reports."""
    
    def __init__(self, pretty: bool = True, indent: int = 2):
        self.pretty = pretty
        self.indent = indent
    
    def generate(self, data: Dict[str, Any]) -> str:
        """
        Generate JSON report.
        
        Args:
            data: Scan results data
            
        Returns:
            JSON formatted string
        """
        # Add metadata
        report = {
            "report_metadata": {
                "generator": "MWAVS - Modular Web Application Vulnerability Scanner",
                "version": "1.0.0",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "format_version": "1.0",
            },
            **data
        }
        
        if self.pretty:
            return json.dumps(report, indent=self.indent, default=str, ensure_ascii=False)
        else:
            return json.dumps(report, default=str, ensure_ascii=False)