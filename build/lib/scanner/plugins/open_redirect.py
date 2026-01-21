"""
Open Redirect Detection Plugin.
Detects open redirect vulnerabilities that allow redirecting users to external sites.
"""

import re
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse, urljoin, quote

from .base import ActivePlugin, PluginContext, PluginResult, PluginCategory
from scanner.core.engine import HTTPEngine
from scanner.core.request_wrapper import RequestWrapper, HTTPMethod, RequestBuilder
from scanner.core.response_wrapper import ResponseWrapper
from scanner.core.utils import Finding, PayloadEncoder, RandomUtils
from scanner.core.exceptions import RequestException


class OpenRedirectPlugin(ActivePlugin):
    """
    Open Redirect vulnerability detection plugin.
    
    Features:
    - Multiple payload formats for bypass
    - Redirect validation via Location header
    - JavaScript redirect detection
    - Meta refresh redirect detection
    - Protocol-relative URL detection
    """
    
    name = "openredirect"
    description = "Open Redirect vulnerability detection module"
    category = PluginCategory.INJECTION
    author = "Security Team"
    version = "1.0.0"
    default_severity = "medium"
    
    cvss_score = 4.7
    cwe_id = "CWE-601"
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
        "https://cwe.mitre.org/data/definitions/601.html",
        "https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
    ]
    
    # Target domain for testing
    EVIL_DOMAIN = "evil.com"
    
    # Payload patterns for open redirect testing
    REDIRECT_PAYLOADS = [
        # Basic payloads
        "https://{evil}",
        "http://{evil}",
        "//{evil}",
        
        # Backslash bypass
        "/\\{evil}",
        "\\/\\/{evil}",
        "\\\\{evil}",
        
        # URL encoding
        "https://{evil}%00",
        "https://{evil}%0d%0a",
        
        # @ bypass
        "https://google.com@{evil}",
        "https://expected-host@{evil}",
        
        # Fragment bypass
        "https://{evil}#google.com",
        "https://google.com#{evil}",
        
        # Path confusion
        "https://google.com.{evil}",
        "https://{evil}/google.com",
        "https://{evil}%2F%2Fgoogle.com",
        
        # Protocol handlers
        "javascript://google.com/%0d%0aalert(1)",
        "data:text/html,<script>location='{evil}'</script>",
        
        # Double URL encoding
        "https://%25%36%35%25%37%36%25%36%39%25%36%63%25%32%65%25%36%33%25%36%66%25%36%64",
        
        # Null byte
        "https://google.com%00.{evil}",
        
        # Tab and newline
        "https://google.com%09.{evil}",
        "https://google.com%0a.{evil}",
        
        # Different schemes
        "///{evil}",
        "///\\{evil}",
        "/////{evil}",
        
        # Unicode tricks
        "https://google.com%E3%80%82{evil}",  # Ideographic full stop
        
        # Case variations
        "HtTpS://{evil}",
        "HTTPS://{evil}",
        
        # Whitelisted domain confusion
        "/redirect?url=//{evil}",
        "?url=//{evil}&trusted=true",
        
        # Encoded slashes
        "https:{evil}",
        "https:/{evil}",
        "//{evil}%2f%2e%2e",
        
        # Multiple redirects
        "https://google.com/url?q=https://{evil}",
    ]
    
    # Common redirect parameters
    REDIRECT_PARAMS = [
        'url', 'redirect', 'redirect_url', 'redirect_uri', 'redir',
        'return', 'return_url', 'returnUrl', 'returnTo', 'return_to',
        'next', 'next_url', 'nextUrl', 'forward', 'forward_url',
        'dest', 'destination', 'target', 'target_url', 'to',
        'go', 'goto', 'link', 'out', 'view', 'continue',
        'path', 'data', 'reference', 'site', 'html', 'page',
        'callback', 'callback_url', 'jump', 'jump_url',
        'success', 'success_url', 'error_url', 'cancel_url',
        'checkout_url', 'login_url', 'logout_url',
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        self._tested_params: set = set()
    
    def run(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> PluginResult:
        """Execute open redirect scanning."""
        result = self.create_result()
        
        try:
            # Get injection points
            injection_points = self.get_injection_points(target, context)
            
            # Also look for common redirect parameters not in injection points
            additional_params = self._find_redirect_params(target, context)
            
            # Combine all parameters to test
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
                
                # Skip if we've already tested this param
                if param_name in self._tested_params:
                    continue
                
                self._tested_params.add(param_name)
                self.logger.debug(f"Testing redirect param: {param_name}")
                
                findings = self._test_redirect_parameter(
                    engine, target, param_name, param_value,
                    location, context
                )
                
                for finding in findings:
                    result.add_finding(finding)
                    result.requests_made += 1
                    
                    if self.config.plugins.stop_on_first_finding:
                        return self.postprocess(result)
        
        except Exception as e:
            result.add_error(f"Open redirect scan error: {str(e)}")
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
        """Test a parameter for open redirect."""
        return self._test_redirect_parameter(
            engine, target, param_name, param_value, location, context
        )
    
    def _find_redirect_params(
        self,
        target: str,
        context: PluginContext
    ) -> List[str]:
        """Find potential redirect parameters based on naming patterns."""
        found_params = []
        
        # Check existing parameters
        for param in list(context.parameters.keys()) + list(context.body_params.keys()):
            param_lower = param.lower()
            if any(rp in param_lower for rp in self.REDIRECT_PARAMS):
                found_params.append(param)
        
        # Add common redirect params for testing
        for param in self.REDIRECT_PARAMS[:10]:  # Test first 10 common params
            if param not in [p.lower() for p in found_params]:
                found_params.append(param)
        
        return found_params
    
    def _test_redirect_parameter(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext
    ) -> List[Finding]:
        """Test a specific parameter for open redirect vulnerabilities."""
        findings = []
        
        for payload_template in self.REDIRECT_PAYLOADS:
            if self.should_stop():
                break
            
            payload = payload_template.format(evil=self.EVIL_DOMAIN)
            
            try:
                # Build request without following redirects
                if location == 'url':
                    params = dict(context.parameters)
                    params[param_name] = payload
                    
                    request = (
                        RequestBuilder(target)
                        .params(params)
                        .headers(context.headers)
                        .cookies(context.cookies)
                        .no_redirects()
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
                        .no_redirects()
                        .build()
                    )
                
                response = engine.request(request, follow_redirects=False)
                
                # Check for redirect to evil domain
                redirect_result = self._check_redirect(response, payload)
                
                if redirect_result:
                    redirect_type, redirect_url, confidence = redirect_result
                    
                    finding = self.create_finding(
                        vulnerability_type=f"Open Redirect ({redirect_type})",
                        url=target,
                        severity="medium",
                        confidence=confidence,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Redirects to: {redirect_url}",
                        description=(
                            f"Open redirect vulnerability detected in parameter "
                            f"'{param_name}'. The application redirects users to "
                            f"external URLs specified in the {redirect_type.lower()}. "
                            f"This can be exploited for phishing attacks."
                        ),
                        remediation=(
                            "Implement a whitelist of allowed redirect destinations. "
                            "Avoid using user input directly in redirect URLs. "
                            "Use relative URLs for internal redirects. "
                            "Validate that redirect URLs belong to trusted domains."
                        ),
                        request_data=request.to_dict(),
                        response_data={
                            'status_code': response.status_code,
                            'location': response.location,
                            'redirect_type': redirect_type,
                        }
                    )
                    
                    findings.append(finding)
                    
                    # One confirmed redirect per parameter is enough
                    break
            
            except RequestException as e:
                self.logger.debug(f"Request failed: {e}")
                continue
        
        return findings
    
    def _check_redirect(
        self,
        response: ResponseWrapper,
        payload: str
    ) -> Optional[tuple]:
        """
        Check if response indicates a redirect to the evil domain.
        
        Returns:
            Tuple of (redirect_type, redirect_url, confidence) or None
        """
        # Check Location header (HTTP redirect)
        if response.is_redirect and response.location:
            location = response.location.lower()
            
            if self._is_evil_redirect(location):
                return ("Location Header", response.location, 95.0)
        
        # Check for meta refresh
        meta_redirect = self._check_meta_refresh(response.text)
        if meta_redirect and self._is_evil_redirect(meta_redirect):
            return ("Meta Refresh", meta_redirect, 90.0)
        
        # Check for JavaScript redirect
        js_redirect = self._check_javascript_redirect(response.text)
        if js_redirect and self._is_evil_redirect(js_redirect):
            return ("JavaScript", js_redirect, 85.0)
        
        # Check for reflection without encoding (potential DOM-based)
        if self.EVIL_DOMAIN in response.text:
            # Look for assignment to location
            if re.search(
                rf'(location\s*=|location\.href\s*=|window\.location\s*=).*{re.escape(self.EVIL_DOMAIN)}',
                response.text,
                re.IGNORECASE
            ):
                return ("DOM-based", self.EVIL_DOMAIN, 75.0)
        
        return None
    
    def _is_evil_redirect(self, url: str) -> bool:
        """Check if URL redirects to evil domain."""
        url_lower = url.lower()
        
        # Direct match
        if self.EVIL_DOMAIN in url_lower:
            return True
        
        # Parse the URL to check the host
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                host = parsed.netloc.lower()
                # Check for evil domain or subdomains
                if host == self.EVIL_DOMAIN or host.endswith(f'.{self.EVIL_DOMAIN}'):
                    return True
        except Exception:
            pass
        
        return False
    
    def _check_meta_refresh(self, body: str) -> Optional[str]:
        """Check for meta refresh redirect."""
        pattern = r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^"\'\s>]+)'
        match = re.search(pattern, body, re.IGNORECASE)
        
        if match:
            return match.group(1)
        
        return None
    
    def _check_javascript_redirect(self, body: str) -> Optional[str]:
        """Check for JavaScript redirect."""
        patterns = [
            r'location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
            r'location\.assign\s*\(\s*["\']([^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                url = match.group(1)
                if self._is_evil_redirect(url):
                    return url
        
        return None