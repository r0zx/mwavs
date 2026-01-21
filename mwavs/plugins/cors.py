"""
CORS Misconfiguration Detection Plugin.
Detects Cross-Origin Resource Sharing security misconfigurations.
"""

import re
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urlparse

from .base import BasePlugin, PluginContext, PluginResult, PluginCategory
from mwavs.core.engine import HTTPEngine
from mwavs.core.request_wrapper import RequestWrapper, HTTPMethod, RequestBuilder
from mwavs.core.response_wrapper import ResponseWrapper
from mwavs.core.utils import Finding, URLUtils
from mwavs.core.exceptions import RequestException


class CORSPlugin(BasePlugin):
    """
    CORS Misconfiguration detection plugin.
    
    Features:
    - Wildcard origin detection
    - Reflected origin detection
    - Null origin bypass detection
    - Credentialed CORS checks
    - Subdomain trust analysis
    - Pre-flight request testing
    """
    
    name = "cors"
    description = "CORS Misconfiguration detection module"
    category = PluginCategory.CONFIGURATION
    author = "Security Team"
    version = "1.0.0"
    default_severity = "medium"
    
    cvss_score = 5.3
    cwe_id = "CWE-942"
    references = [
        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
        "https://portswigger.net/web-security/cors",
        "https://cwe.mitre.org/data/definitions/942.html",
    ]
    
    # Test origins for CORS probing
    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",  # null origin
        "https://subdomain.{target_domain}",
        "https://{target_domain}.evil.com",
        "https://{target_domain}evil.com",
        "https://evil{target_domain}",
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
    
    def run(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> PluginResult:
        """Execute CORS misconfiguration scanning."""
        result = self.create_result()
        
        try:
            # Extract target domain for payload generation
            target_domain = URLUtils.get_domain(target)
            
            # Test various CORS misconfigurations
            findings = []
            
            # Test 1: Wildcard origin
            wildcard_finding = self._test_wildcard_origin(engine, target, context)
            if wildcard_finding:
                findings.append(wildcard_finding)
            
            # Test 2: Reflected origin
            reflected_finding = self._test_reflected_origin(
                engine, target, context, target_domain
            )
            if reflected_finding:
                findings.append(reflected_finding)
            
            # Test 3: Null origin
            null_finding = self._test_null_origin(engine, target, context)
            if null_finding:
                findings.append(null_finding)
            
            # Test 4: Subdomain trust issues
            subdomain_finding = self._test_subdomain_trust(
                engine, target, context, target_domain
            )
            if subdomain_finding:
                findings.append(subdomain_finding)
            
            # Test 5: Credentialed requests
            cred_finding = self._test_credentialed_cors(
                engine, target, context
            )
            if cred_finding:
                findings.append(cred_finding)
            
            # Test 6: Pre-flight bypass
            preflight_finding = self._test_preflight_bypass(
                engine, target, context
            )
            if preflight_finding:
                findings.append(preflight_finding)
            
            for finding in findings:
                result.add_finding(finding)
                result.requests_made += 1
        
        except Exception as e:
            result.add_error(f"CORS scan error: {str(e)}")
            self.logger.error(f"Error during scan: {e}", exc_info=True)
        
        return self.postprocess(result)
    
    def _test_wildcard_origin(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> Optional[Finding]:
        """Test for wildcard (*) ACAO header."""
        try:
            # Send request with arbitrary origin
            request = (
                RequestBuilder(target)
                .header("Origin", "https://evil.com")
                .headers(context.headers)
                .cookies(context.cookies)
                .build()
            )
            
            response = engine.request(request)
            
            acao = response.get_header("Access-Control-Allow-Origin")
            acac = response.get_header("Access-Control-Allow-Credentials")
            
            if acao == "*":
                # Wildcard is only dangerous with credentials
                if acac and acac.lower() == "true":
                    severity = "high"
                    description = (
                        "CORS wildcard (*) origin with credentials allowed. "
                        "This is a severe misconfiguration that allows any website "
                        "to make authenticated requests."
                    )
                else:
                    severity = "low"
                    description = (
                        "CORS wildcard (*) origin detected. While credentials "
                        "are not allowed with wildcards, this may still expose "
                        "sensitive information to any origin."
                    )
                
                return self.create_finding(
                    vulnerability_type="CORS Wildcard Origin",
                    url=target,
                    severity=severity,
                    confidence=95.0,
                    evidence=(
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac or 'Not set'}"
                    ),
                    description=description,
                    remediation=(
                        "Implement a whitelist of trusted origins instead of "
                        "using wildcards. Validate the Origin header against "
                        "the whitelist before reflecting it."
                    ),
                )
        
        except RequestException as e:
            self.logger.debug(f"Wildcard test failed: {e}")
        
        return None
    
    def _test_reflected_origin(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext,
        target_domain: str
    ) -> Optional[Finding]:
        """Test for reflected origin (ACAO reflects any origin)."""
        evil_origins = [
            "https://evil.com",
            "https://attacker.com",
            f"https://not{target_domain}",
        ]
        
        for evil_origin in evil_origins:
            try:
                request = (
                    RequestBuilder(target)
                    .header("Origin", evil_origin)
                    .headers(context.headers)
                    .cookies(context.cookies)
                    .build()
                )
                
                response = engine.request(request)
                
                acao = response.get_header("Access-Control-Allow-Origin")
                acac = response.get_header("Access-Control-Allow-Credentials")
                
                if acao and acao.lower() == evil_origin.lower():
                    # Origin is reflected - this is vulnerable
                    severity = "high" if (acac and acac.lower() == "true") else "medium"
                    
                    return self.create_finding(
                        vulnerability_type="CORS Reflected Origin",
                        url=target,
                        severity=severity,
                        confidence=95.0,
                        evidence=(
                            f"Origin sent: {evil_origin}\n"
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac or 'Not set'}"
                        ),
                        description=(
                            "The server reflects the Origin header in the "
                            "Access-Control-Allow-Origin response without validation. "
                            "This allows any website to make cross-origin requests."
                        ),
                        remediation=(
                            "Implement strict origin validation. Maintain a whitelist "
                            "of allowed origins and only reflect origins that match "
                            "the whitelist exactly."
                        ),
                    )
            
            except RequestException:
                continue
        
        return None
    
    def _test_null_origin(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> Optional[Finding]:
        """Test for null origin acceptance."""
        try:
            request = (
                RequestBuilder(target)
                .header("Origin", "null")
                .headers(context.headers)
                .cookies(context.cookies)
                .build()
            )
            
            response = engine.request(request)
            
            acao = response.get_header("Access-Control-Allow-Origin")
            acac = response.get_header("Access-Control-Allow-Credentials")
            
            if acao and acao.lower() == "null":
                severity = "high" if (acac and acac.lower() == "true") else "medium"
                
                return self.create_finding(
                    vulnerability_type="CORS Null Origin Allowed",
                    url=target,
                    severity=severity,
                    confidence=90.0,
                    evidence=(
                        f"Origin sent: null\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac or 'Not set'}"
                    ),
                    description=(
                        "The server accepts 'null' as a valid origin. "
                        "The null origin can be triggered by sandboxed iframes, "
                        "local file access, and certain redirect scenarios, "
                        "enabling attacks from these contexts."
                    ),
                    remediation=(
                        "Do not include 'null' in the list of allowed origins. "
                        "Reject requests with null origin unless specifically required."
                    ),
                )
        
        except RequestException as e:
            self.logger.debug(f"Null origin test failed: {e}")
        
        return None
    
    def _test_subdomain_trust(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext,
        target_domain: str
    ) -> Optional[Finding]:
        """Test for subdomain trust issues."""
        # Test various subdomain-like origins
        subdomain_origins = [
            f"https://evil.{target_domain}",
            f"https://{target_domain}.evil.com",
            f"https://subdomain.{target_domain}",
            f"https://test.{target_domain}",
        ]
        
        trusted_subdomains = []
        
        for origin in subdomain_origins:
            try:
                request = (
                    RequestBuilder(target)
                    .header("Origin", origin)
                    .headers(context.headers)
                    .cookies(context.cookies)
                    .build()
                )
                
                response = engine.request(request)
                
                acao = response.get_header("Access-Control-Allow-Origin")
                
                if acao and acao.lower() == origin.lower():
                    trusted_subdomains.append(origin)
            
            except RequestException:
                continue
        
        if trusted_subdomains:
            # Check if potentially dangerous patterns are trusted
            dangerous = [
                o for o in trusted_subdomains 
                if 'evil' in o or target_domain + '.' in o
            ]
            
            if dangerous:
                return self.create_finding(
                    vulnerability_type="CORS Insecure Subdomain Trust",
                    url=target,
                    severity="medium",
                    confidence=85.0,
                    evidence=f"Trusted origins: {', '.join(dangerous)}",
                    description=(
                        "The server trusts subdomains or domain variations that "
                        "could be controlled by attackers. This includes patterns "
                        "like 'target.com.evil.com' or arbitrary subdomains."
                    ),
                    remediation=(
                        "Use exact origin matching instead of pattern-based matching. "
                        "Only trust explicitly whitelisted subdomains. "
                        "Be careful with regex patterns that might match unintended origins."
                    ),
                )
        
        return None
    
    def _test_credentialed_cors(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> Optional[Finding]:
        """Test for dangerous credentialed CORS."""
        try:
            request = (
                RequestBuilder(target)
                .header("Origin", "https://evil.com")
                .headers(context.headers)
                .cookies(context.cookies)
                .build()
            )
            
            response = engine.request(request)
            
            acao = response.get_header("Access-Control-Allow-Origin")
            acac = response.get_header("Access-Control-Allow-Credentials")
            
            # Check for dangerous combination
            if (acao and 
                acao.lower() != "*" and 
                acac and 
                acac.lower() == "true" and
                acao.lower() == "https://evil.com"):
                
                return self.create_finding(
                    vulnerability_type="CORS Credentialed Request Misconfiguration",
                    url=target,
                    severity="high",
                    confidence=95.0,
                    evidence=(
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    description=(
                        "The server allows credentialed cross-origin requests from "
                        "untrusted origins. This enables attackers to make authenticated "
                        "requests and steal sensitive data on behalf of victims."
                    ),
                    remediation=(
                        "Only allow credentials for explicitly trusted origins. "
                        "Implement strict origin validation before allowing credentials. "
                        "Consider using SameSite cookies as additional protection."
                    ),
                )
        
        except RequestException as e:
            self.logger.debug(f"Credentialed CORS test failed: {e}")
        
        return None
    
    def _test_preflight_bypass(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> Optional[Finding]:
        """Test for pre-flight request bypass issues."""
        try:
            # Send OPTIONS pre-flight request
            request = (
                RequestBuilder(target)
                .method(HTTPMethod.OPTIONS)
                .header("Origin", "https://evil.com")
                .header("Access-Control-Request-Method", "PUT")
                .header("Access-Control-Request-Headers", "X-Custom-Header")
                .headers(context.headers)
                .build()
            )
            
            response = engine.request(request)
            
            # Check pre-flight response headers
            acam = response.get_header("Access-Control-Allow-Methods")
            acah = response.get_header("Access-Control-Allow-Headers")
            acao = response.get_header("Access-Control-Allow-Origin")
            
            dangerous_methods = []
            if acam:
                methods = [m.strip().upper() for m in acam.split(',')]
                dangerous = {'PUT', 'DELETE', 'PATCH'}
                dangerous_methods = [m for m in methods if m in dangerous]
            
            dangerous_headers = []
            if acah:
                headers = [h.strip().lower() for h in acah.split(',')]
                # Check for wildcard or dangerous headers
                if '*' in headers:
                    dangerous_headers = ['* (wildcard)']
                elif 'x-custom-header' in headers:
                    dangerous_headers = ['custom headers allowed']
            
            if acao == "https://evil.com" and (dangerous_methods or dangerous_headers):
                return self.create_finding(
                    vulnerability_type="CORS Pre-flight Misconfiguration",
                    url=target,
                    severity="medium",
                    confidence=80.0,
                    evidence=(
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Methods: {acam or 'Not set'}\n"
                        f"Access-Control-Allow-Headers: {acah or 'Not set'}"
                    ),
                    description=(
                        "The server's CORS pre-flight response allows potentially "
                        f"dangerous methods ({dangerous_methods}) or headers from "
                        "untrusted origins."
                    ),
                    remediation=(
                        "Restrict allowed methods to only those necessary. "
                        "Avoid using wildcard (*) for allowed headers. "
                        "Validate origin before allowing sensitive methods."
                    ),
                )
        
        except RequestException as e:
            self.logger.debug(f"Preflight test failed: {e}")
        
        return None