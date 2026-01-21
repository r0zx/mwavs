"""
Server-Side Request Forgery (SSRF) Detection Plugin.
Detects SSRF vulnerabilities that allow attackers to make server-side requests.
"""

import re
import socket
import time
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urlparse, quote

from .base import ActivePlugin, PluginContext, PluginResult, PluginCategory
from mwavs.core.engine import HTTPEngine
from mwavs.core.request_wrapper import RequestWrapper, HTTPMethod, RequestBuilder
from mwavs.core.response_wrapper import ResponseWrapper
from mwavs.core.utils import Finding, PayloadEncoder, RandomUtils
from mwavs.core.exceptions import RequestException


class SSRFPlugin(ActivePlugin):
    """
    Server-Side Request Forgery (SSRF) detection plugin.
    
    Features:
    - Out-of-band detection simulation
    - Localhost/internal IP probing
    - Cloud metadata service probing
    - Multiple bypass techniques
    - Protocol smuggling attempts
    """
    
    name = "ssrf"
    description = "Server-Side Request Forgery (SSRF) detection module"
    category = PluginCategory.INJECTION
    author = "Security Team"
    version = "1.0.0"
    default_severity = "high"
    
    cvss_score = 7.5
    cwe_id = "CWE-918"
    references = [
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://cwe.mitre.org/data/definitions/918.html",
        "https://portswigger.net/web-security/ssrf",
    ]
    
    # Internal IP ranges
    INTERNAL_IPS = [
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "::1",
        "0177.0.0.1",  # Octal
        "2130706433",  # Decimal
        "0x7f.0x0.0x0.0x1",  # Hex
        "127.0.0.1.nip.io",
        "127.1",
        "[::ffff:127.0.0.1]",
        "[::]",
    ]
    
    # Common internal ports to probe
    INTERNAL_PORTS = [
        80, 443, 8080, 8443, 22, 21, 25, 110, 143,
        3306, 5432, 6379, 27017, 9200, 11211,
    ]
    
    # Cloud metadata endpoints
    CLOUD_METADATA = {
        'aws': [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ],
        'gcp': [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",
        ],
        'azure': [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token",
        ],
        'digitalocean': [
            "http://169.254.169.254/metadata/v1/",
        ],
        'alibaba': [
            "http://100.100.100.200/latest/meta-data/",
        ],
    }
    
    # SSRF bypass techniques
    BYPASS_TECHNIQUES = [
        # URL encoding
        lambda url: quote(url, safe=''),
        
        # Double URL encoding
        lambda url: quote(quote(url, safe=''), safe=''),
        
        # IPv6 localhost
        lambda url: url.replace('127.0.0.1', '[::ffff:127.0.0.1]'),
        
        # Decimal IP
        lambda url: url.replace('127.0.0.1', '2130706433'),
        
        # Octal IP
        lambda url: url.replace('127.0.0.1', '0177.0.0.1'),
        
        # Hex IP
        lambda url: url.replace('127.0.0.1', '0x7f.0x0.0x0.0x1'),
        
        # Short localhost
        lambda url: url.replace('127.0.0.1', '127.1'),
        
        # With @ bypass
        lambda url: url.replace('://', '://anything@'),
        
        # With fragment
        lambda url: url + '#',
        
        # URL with port
        lambda url: url.replace('.1/', '.1:80/'),
    ]
    
    # Common SSRF-vulnerable parameters
    SSRF_PARAMS = [
        'url', 'uri', 'path', 'dest', 'redirect', 'out',
        'site', 'html', 'data', 'load', 'file', 'document',
        'folder', 'root', 'pg', 'style', 'pdf', 'img',
        'image', 'file', 'filename', 'page', 'target',
        'u', 'link', 'src', 'source', 'domain', 'host',
        'fetch', 'proxy', 'download', 'include', 'feed',
        'callback', 'request', 'endpoint', 'api', 'webhook',
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        self._oob_domain = None  # For OOB detection (requires external setup)
    
    def run(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> PluginResult:
        """Execute SSRF scanning."""
        result = self.create_result()
        
        try:
            # Get injection points
            injection_points = self.get_injection_points(target, context)
            
            # Add common SSRF parameters
            additional_params = self._find_ssrf_params(target, context)
            
            all_params = set()
            for param_name, param_value, location in injection_points:
                all_params.add((param_name, param_value, location))
            
            for param_name in additional_params:
                if param_name not in [p[0] for p in all_params]:
                    all_params.add((param_name, "", "url"))
            
            for param_name, param_value, location in all_params:
                if self.should_stop():
                    result.aborted = True
                    result.abort_reason = "Stop requested"
                    break
                
                self.logger.debug(f"Testing SSRF param: {param_name}")
                
                findings = self._test_ssrf_parameter(
                    engine, target, param_name, param_value,
                    location, context
                )
                
                for finding in findings:
                    result.add_finding(finding)
                    result.requests_made += 1
                    
                    if self.config.plugins.stop_on_first_finding:
                        return self.postprocess(result)
        
        except Exception as e:
            result.add_error(f"SSRF scan error: {str(e)}")
            self.logger.error(f"Error during scan: {e}", exc_info=True)
        
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
        """Test a parameter for SSRF."""
        return self._test_ssrf_parameter(
            engine, target, param_name, param_value, location, context
        )
    
    def _find_ssrf_params(
        self,
        target: str,
        context: PluginContext
    ) -> List[str]:
        """Find potential SSRF parameters."""
        found_params = []
        
        # Check existing parameters
        for param in list(context.parameters.keys()) + list(context.body_params.keys()):
            param_lower = param.lower()
            if any(sp in param_lower for sp in self.SSRF_PARAMS):
                found_params.append(param)
        
        return found_params
    
    def _test_ssrf_parameter(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext
    ) -> List[Finding]:
        """Test a specific parameter for SSRF vulnerabilities."""
        findings = []
        
        # Test 1: Localhost probing
        localhost_finding = self._test_localhost(
            engine, target, param_name, location, context
        )
        if localhost_finding:
            findings.append(localhost_finding)
            if self.config.plugins.stop_on_first_finding:
                return findings
        
        # Test 2: Cloud metadata endpoints
        metadata_findings = self._test_cloud_metadata(
            engine, target, param_name, location, context
        )
        findings.extend(metadata_findings)
        if findings and self.config.plugins.stop_on_first_finding:
            return findings
        
        # Test 3: Internal network probing
        internal_finding = self._test_internal_network(
            engine, target, param_name, location, context
        )
        if internal_finding:
            findings.append(internal_finding)
        
        return findings
    
    def _test_localhost(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        location: str,
        context: PluginContext
    ) -> Optional[Finding]:
        """Test for localhost access via SSRF."""
        
        # Get baseline for comparison
        baseline_response = self._get_baseline(
            engine, target, param_name, "http://example.com", location, context
        )
        
        for localhost_variant in self.INTERNAL_IPS:
            if self.should_stop():
                break
            
            for port in [80, 8080, 443]:
                payload = f"http://{localhost_variant}:{port}/"
                
                # Try with bypass techniques
                payloads_to_try = [payload]
                for bypass_func in self.BYPASS_TECHNIQUES[:5]:  # Limit bypasses
                    try:
                        bypassed = bypass_func(payload)
                        if bypassed != payload:
                            payloads_to_try.append(bypassed)
                    except Exception:
                        pass
                
                for test_payload in payloads_to_try:
                    try:
                        response = self._send_ssrf_request(
                            engine, target, param_name, test_payload,
                            location, context
                        )
                        
                        if response and self._is_ssrf_successful(
                            response, baseline_response, 'localhost'
                        ):
                            return self.create_finding(
                                vulnerability_type="SSRF - Localhost Access",
                                url=target,
                                severity="high",
                                confidence=85.0,
                                parameter=param_name,
                                payload=test_payload,
                                evidence=self._extract_ssrf_evidence(response),
                                description=(
                                    f"Server-Side Request Forgery vulnerability detected. "
                                    f"The application can be tricked into making requests "
                                    f"to localhost/internal services via parameter '{param_name}'."
                                ),
                                remediation=(
                                    "Implement a strict allowlist of permitted URLs/domains. "
                                    "Block requests to internal IP ranges and localhost. "
                                    "Use a URL parser to validate and sanitize URLs. "
                                    "Consider using a dedicated service for external requests."
                                ),
                                request_data={"parameter": param_name, "payload": test_payload},
                                response_data={
                                    "status_code": response.status_code,
                                    "content_length": response.content_length,
                                },
                            )
                    
                    except RequestException:
                        continue
        
        return None
    
    def _test_cloud_metadata(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        location: str,
        context: PluginContext
    ) -> List[Finding]:
        """Test for cloud metadata endpoint access."""
        findings = []
        
        baseline_response = self._get_baseline(
            engine, target, param_name, "http://example.com", location, context
        )
        
        for cloud_provider, endpoints in self.CLOUD_METADATA.items():
            if self.should_stop():
                break
            
            for endpoint in endpoints:
                try:
                    response = self._send_ssrf_request(
                        engine, target, param_name, endpoint,
                        location, context
                    )
                    
                    if response and self._is_metadata_response(
                        response, cloud_provider
                    ):
                        finding = self.create_finding(
                            vulnerability_type=f"SSRF - {cloud_provider.upper()} Metadata Access",
                            url=target,
                            severity="critical",
                            confidence=95.0,
                            parameter=param_name,
                            payload=endpoint,
                            evidence=self._extract_ssrf_evidence(response),
                            description=(
                                f"Critical SSRF vulnerability allowing access to "
                                f"{cloud_provider.upper()} cloud metadata service. "
                                f"This can lead to credential theft and full "
                                f"cloud account compromise."
                            ),
                            remediation=(
                                "Immediately block access to cloud metadata IPs "
                                "(169.254.169.254, metadata.google.internal, etc.). "
                                "Use IMDSv2 on AWS which requires session tokens. "
                                "Implement network-level controls to block metadata access."
                            ),
                        )
                        findings.append(finding)
                        
                        # One metadata finding is enough
                        return findings
                
                except RequestException:
                    continue
        
        return findings
    
    def _test_internal_network(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        location: str,
        context: PluginContext
    ) -> Optional[Finding]:
        """Test for internal network access."""
        
        # Common internal IP patterns
        internal_ranges = [
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.0.1/",
            "http://192.168.1.1/",
        ]
        
        baseline_response = self._get_baseline(
            engine, target, param_name, "http://example.com", location, context
        )
        
        for internal_url in internal_ranges:
            if self.should_stop():
                break
            
            try:
                response = self._send_ssrf_request(
                    engine, target, param_name, internal_url,
                    location, context
                )
                
                if response and self._is_ssrf_successful(
                    response, baseline_response, 'internal'
                ):
                    return self.create_finding(
                        vulnerability_type="SSRF - Internal Network Access",
                        url=target,
                        severity="high",
                        confidence=80.0,
                        parameter=param_name,
                        payload=internal_url,
                        evidence=self._extract_ssrf_evidence(response),
                        description=(
                            f"SSRF vulnerability allowing access to internal network "
                            f"resources via parameter '{param_name}'. This can be used "
                            f"to scan internal networks and access internal services."
                        ),
                        remediation=(
                            "Block requests to private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x). "
                            "Implement egress filtering. Use an allowlist for permitted destinations."
                        ),
                    )
            
            except RequestException:
                continue
        
        return None
    
    def _get_baseline(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        safe_url: str,
        location: str,
        context: PluginContext
    ) -> Optional[ResponseWrapper]:
        """Get baseline response for comparison."""
        try:
            return self._send_ssrf_request(
                engine, target, param_name, safe_url, location, context
            )
        except RequestException:
            return None
    
    def _send_ssrf_request(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        payload: str,
        location: str,
        context: PluginContext
    ) -> ResponseWrapper:
        """Send request with SSRF payload."""
        if location == 'url':
            params = dict(context.parameters)
            params[param_name] = payload
            
            request = (
                RequestBuilder(target)
                .params(params)
                .headers(context.headers)
                .cookies(context.cookies)
                .timeout(10)  # Shorter timeout for SSRF
                .build()
            )
        else:
            body_params = dict(context.body_params)
            body_params[param_name] = payload
            
            request = (
                RequestBuilder(target)
                .post()
                .data(body_params)
                .headers(context.headers)
                .cookies(context.cookies)
                .timeout(10)
                .build()
            )
        
        return engine.request(request)
    
    def _is_ssrf_successful(
        self,
        response: ResponseWrapper,
        baseline: Optional[ResponseWrapper],
        ssrf_type: str
    ) -> bool:
        """Determine if SSRF was successful based on response analysis."""
        
        # Check for error indicators (meaning server tried to fetch)
        if response.status_code >= 500:
            # Server error might indicate failed internal request
            error_indicators = [
                'connection refused',
                'connection timed out',
                'could not connect',
                'network unreachable',
                'no route to host',
            ]
            body_lower = response.text.lower()
            if any(ind in body_lower for ind in error_indicators):
                return True
        
        # Check for significant differences from baseline
        if baseline:
            # Different status code
            if response.status_code != baseline.status_code:
                if response.status_code in [200, 301, 302, 403]:
                    return True
            
            # Significant length difference
            len_diff = abs(response.content_length - baseline.content_length)
            if len_diff > 1000:
                return True
            
            # Different content type
            if response.content_type != baseline.content_type:
                return True
        
        # Check for internal service indicators in response
        internal_indicators = [
            'apache',
            'nginx',
            'iis',
            'tomcat',
            'localhost',
            '127.0.0.1',
            'internal',
            'intranet',
            'private',
            'admin',
        ]
        
        body_lower = response.text.lower()
        if any(ind in body_lower for ind in internal_indicators):
            return True
        
        return False
    
    def _is_metadata_response(
        self,
        response: ResponseWrapper,
        cloud_provider: str
    ) -> bool:
        """Check if response contains cloud metadata."""
        
        if response.status_code != 200:
            return False
        
        body = response.text.lower()
        
        # Provider-specific indicators
        indicators = {
            'aws': [
                'ami-id', 'instance-id', 'instance-type', 'local-ipv4',
                'security-credentials', 'iam', 'meta-data',
            ],
            'gcp': [
                'project-id', 'zone', 'machine-type', 'service-accounts',
                'instance/attributes', 'computemetadata',
            ],
            'azure': [
                'vmid', 'subscriptionid', 'resourcegroupname',
                'location', 'azureenvironment',
            ],
            'digitalocean': [
                'droplet_id', 'hostname', 'region', 'interfaces',
            ],
            'alibaba': [
                'instance-id', 'region-id', 'zone-id',
            ],
        }
        
        provider_indicators = indicators.get(cloud_provider, [])
        
        # Check for provider-specific content
        matches = sum(1 for ind in provider_indicators if ind in body)
        
        return matches >= 2
    
    def _extract_ssrf_evidence(self, response: ResponseWrapper) -> str:
        """Extract evidence from SSRF response."""
        evidence_parts = [
            f"Status Code: {response.status_code}",
            f"Content Length: {response.content_length}",
            f"Content Type: {response.content_type or 'N/A'}",
        ]
        
        # Add relevant headers
        interesting_headers = ['server', 'x-powered-by', 'via', 'x-forwarded-for']
        for header in interesting_headers:
            value = response.get_header(header)
            if value:
                evidence_parts.append(f"{header}: {value}")
        
        # Add body snippet
        body_snippet = response.text[:500]
        if body_snippet:
            evidence_parts.append(f"\nBody Preview:\n{body_snippet}")
        
        return "\n".join(evidence_parts)