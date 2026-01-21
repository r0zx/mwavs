"""
Directory Enumeration Plugin.
Discovers hidden directories, files, and paths on the target web server.
"""

import re
from typing import List, Optional, Dict, Any, Set, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from .base import BasePlugin, PluginContext, PluginResult, PluginCategory
from scanner.core.engine import HTTPEngine
from scanner.core.request_wrapper import RequestWrapper, HTTPMethod, RequestBuilder
from scanner.core.response_wrapper import ResponseWrapper
from scanner.core.utils import Finding, URLUtils, ResponseAnalyzer
from scanner.core.exceptions import RequestException, WAFBlockException, RateLimitException


@dataclass
class DirectoryResult:
    """Result of a directory/file check."""
    path: str
    status_code: int
    content_length: int
    content_type: Optional[str]
    redirect_url: Optional[str] = None
    interesting: bool = False
    reason: str = ""


class DirectoryEnumPlugin(BasePlugin):
    """
    Directory and file enumeration plugin.
    
    Features:
    - Wordlist-based enumeration
    - Status code analysis
    - Response length comparison for false positive filtering
    - WAF/Rate limit detection and handling
    - File extension fuzzing
    - Recursive enumeration option
    - Smart duplicate detection
    """
    
    name = "dir"
    description = "Directory and file enumeration module"
    category = PluginCategory.ENUMERATION
    author = "Security Team"
    version = "1.0.0"
    default_severity = "info"
    
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/",
    ]
    
    # Status codes indicating interesting results
    SUCCESS_CODES = {200, 201, 202, 203, 204}
    REDIRECT_CODES = {301, 302, 303, 307, 308}
    AUTH_CODES = {401, 403}
    
    # Common extensions to try
    DEFAULT_EXTENSIONS = [
        '', '.php', '.asp', '.aspx', '.jsp', '.html', '.htm',
        '.txt', '.xml', '.json', '.js', '.css', '.bak', '.old',
        '.zip', '.tar.gz', '.sql', '.log', '.conf', '.config',
        '.env', '.git', '.svn', '.htaccess', '.htpasswd',
    ]
    
    # Paths that often indicate interesting findings
    INTERESTING_PATHS = [
        'admin', 'administrator', 'wp-admin', 'phpmyadmin', 'cpanel',
        'manager', 'console', 'dashboard', 'login', 'api', 'backup',
        'config', 'conf', 'database', 'db', 'debug', 'dev', 'test',
        'staging', 'private', 'secret', 'internal', 'hidden',
        '.git', '.svn', '.env', '.htaccess', 'web.config',
        'robots.txt', 'sitemap.xml', 'crossdomain.xml',
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        self._found_paths: Set[str] = set()
        self._baseline_404: Optional[ResponseWrapper] = None
        self._baseline_404_patterns: List[str] = []
        self._rate_limited = False
        self._waf_detected = False
        self._lock = threading.Lock()
    
    def run(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> PluginResult:
        """Execute directory enumeration."""
        result = self.create_result()
        
        try:
            # Get base URL
            base_url = URLUtils.get_base_url(target)
            
            # Establish baseline for 404 detection
            self._establish_baseline(engine, base_url)
            
            # Load wordlist
            wordlist = self._load_wordlist()
            
            if not wordlist:
                result.add_error("No wordlist available for enumeration")
                return self.postprocess(result)
            
            self.logger.info(f"Starting enumeration with {len(wordlist)} words")
            
            # Get extensions to try
            extensions = self._get_extensions()
            
            # Generate all paths to check
            paths_to_check = self._generate_paths(wordlist, extensions)
            
            # Enumerate with threading
            findings = self._enumerate_paths(
                engine, base_url, paths_to_check, result
            )
            
            for finding in findings:
                result.add_finding(finding)
        
        except Exception as e:
            result.add_error(f"Directory enumeration error: {str(e)}")
            self.logger.error(f"Error during enumeration: {e}", exc_info=True)
        
        return self.postprocess(result)
    
    def _establish_baseline(self, engine: HTTPEngine, base_url: str):
        """Establish baseline for 404 page detection."""
        # Request a definitely non-existent path
        random_paths = [
            f"/definitely_not_exists_{hash(base_url) % 10000}",
            f"/random_path_{hash(base_url) % 99999}.html",
            f"/nonexistent_dir_{hash(base_url) % 88888}/",
        ]
        
        for random_path in random_paths:
            try:
                url = f"{base_url}{random_path}"
                response = engine.get(url)
                
                if response.status_code == 404:
                    self._baseline_404 = response
                    
                    # Extract common 404 patterns
                    self._baseline_404_patterns = self._extract_404_patterns(response)
                    
                    self.logger.debug(
                        f"Established 404 baseline: {response.content_length} bytes"
                    )
                    break
                    
            except RequestException:
                continue
    
    def _extract_404_patterns(self, response: ResponseWrapper) -> List[str]:
        """Extract patterns that indicate a 404 page."""
        patterns = []
        body = response.text.lower()
        
        # Common 404 indicators
        indicators = [
            'not found',
            'page not found',
            'file not found',
            '404 error',
            'error 404',
            'does not exist',
            'couldn\'t find',
            'no such file',
            'the page you requested',
        ]
        
        for indicator in indicators:
            if indicator in body:
                patterns.append(indicator)
        
        return patterns
    
    def _load_wordlist(self) -> List[str]:
        """Load wordlist for enumeration."""
        try:
            wordlist = self.wordlist_manager.load('common')
            if wordlist:
                return wordlist
        except Exception as e:
            self.logger.warning(f"Failed to load wordlist: {e}")
        
        # Fallback to built-in common paths
        return [
            'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php',
            'phpmyadmin', 'cpanel', 'webmail', 'mail', 'dashboard',
            'api', 'api/v1', 'api/v2', 'graphql', 'rest',
            'backup', 'backups', 'bak', 'old', 'temp', 'tmp',
            'config', 'conf', 'configuration', 'settings',
            'database', 'db', 'sql', 'mysql', 'data',
            'debug', 'dev', 'development', 'test', 'testing', 'staging',
            'private', 'secret', 'hidden', 'internal',
            'upload', 'uploads', 'files', 'documents', 'docs',
            'images', 'img', 'assets', 'static', 'media',
            'includes', 'include', 'inc', 'lib', 'libs',
            'scripts', 'js', 'javascript', 'css', 'styles',
            'cgi-bin', 'bin', 'scripts',
            '.git', '.git/config', '.git/HEAD', '.gitignore',
            '.svn', '.svn/entries',
            '.env', '.env.local', '.env.production',
            '.htaccess', '.htpasswd', 'web.config',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'server-status', 'server-info',
            'phpinfo.php', 'info.php', 'test.php',
            'readme.txt', 'README.md', 'CHANGELOG.txt',
            'license.txt', 'LICENSE',
            'wp-config.php', 'wp-config.php.bak',
            'xmlrpc.php', 'wp-json',
            'console', 'manager', 'jmx-console',
            'invoker', 'web-console',
        ]
    
    def _get_extensions(self) -> List[str]:
        """Get file extensions to try."""
        return self.DEFAULT_EXTENSIONS[:10]  # Limit for performance
    
    def _generate_paths(
        self,
        wordlist: List[str],
        extensions: List[str]
    ) -> List[str]:
        """Generate all paths to check."""
        paths = set()
        
        for word in wordlist:
            # Clean the word
            word = word.strip().strip('/')
            
            if not word:
                continue
            
            # Add base path
            paths.add(f"/{word}")
            paths.add(f"/{word}/")
            
            # Add with extensions (only if word doesn't already have extension)
            if '.' not in word.split('/')[-1]:
                for ext in extensions:
                    if ext:
                        paths.add(f"/{word}{ext}")
        
        return list(paths)
    
    def _enumerate_paths(
        self,
        engine: HTTPEngine,
        base_url: str,
        paths: List[str],
        result: PluginResult
    ) -> List[Finding]:
        """Enumerate paths with concurrent requests."""
        findings = []
        checked = 0
        total = len(paths)
        
        # Use thread pool for concurrent requests
        max_workers = min(self.config.concurrency.threads, 20)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            
            for path in paths:
                if self.should_stop() or self._rate_limited:
                    break
                
                url = f"{base_url}{path}"
                future = executor.submit(self._check_path, engine, url, path)
                futures[future] = path
            
            for future in as_completed(futures):
                if self.should_stop():
                    break
                
                path = futures[future]
                checked += 1
                
                try:
                    dir_result = future.result()
                    
                    if dir_result and dir_result.interesting:
                        finding = self._create_finding_from_result(
                            dir_result, base_url
                        )
                        findings.append(finding)
                        result.requests_made += 1
                        
                        self.logger.info(
                            f"Found: {path} "
                            f"(Status: {dir_result.status_code}, "
                            f"Size: {dir_result.content_length})"
                        )
                
                except Exception as e:
                    self.logger.debug(f"Error checking {path}: {e}")
                
                # Progress logging
                if checked % 100 == 0:
                    self.logger.debug(f"Progress: {checked}/{total} paths checked")
        
        return findings
    
    def _check_path(
        self,
        engine: HTTPEngine,
        url: str,
        path: str
    ) -> Optional[DirectoryResult]:
        """Check a single path."""
        try:
            response = engine.get(url, timeout=10)
            
            # Check for rate limiting
            if response.status_code == 429:
                self._rate_limited = True
                retry_after = response.get_header('Retry-After')
                self.logger.warning(
                    f"Rate limited. Retry-After: {retry_after}"
                )
                return None
            
            # Analyze the response
            return self._analyze_response(response, path)
        
        except WAFBlockException:
            self._waf_detected = True
            self.logger.warning("WAF blocking detected")
            return None
        
        except RateLimitException:
            self._rate_limited = True
            return None
        
        except RequestException:
            return None
    
    def _analyze_response(
        self,
        response: ResponseWrapper,
        path: str
    ) -> Optional[DirectoryResult]:
        """Analyze response to determine if path exists."""
        status = response.status_code
        
        # Create result object
        result = DirectoryResult(
            path=path,
            status_code=status,
            content_length=response.content_length,
            content_type=response.content_type,
            redirect_url=response.location if response.is_redirect else None,
        )
        
        # Check if it's a success response
        if status in self.SUCCESS_CODES:
            # Verify it's not a soft 404
            if not self._is_soft_404(response):
                result.interesting = True
                result.reason = f"Found (HTTP {status})"
                
                # Check if it's particularly interesting
                for interesting_path in self.INTERESTING_PATHS:
                    if interesting_path.lower() in path.lower():
                        result.reason = f"Sensitive path found (HTTP {status})"
                        break
        
        # Check redirects
        elif status in self.REDIRECT_CODES:
            # Redirect to login might indicate protected area
            if response.location:
                if any(x in response.location.lower() for x in ['login', 'auth', 'signin']):
                    result.interesting = True
                    result.reason = f"Protected resource (redirects to auth)"
        
        # Check auth-required responses
        elif status in self.AUTH_CODES:
            result.interesting = True
            if status == 401:
                result.reason = "Authentication required (HTTP 401)"
            else:
                result.reason = "Forbidden (HTTP 403) - path exists"
        
        # Check for interesting content even on 404
        if not result.interesting and status == 404:
            # Some servers return 404 but still expose information
            if self._has_interesting_content(response):
                result.interesting = True
                result.reason = "Interesting content in 404 response"
        
        return result if result.interesting else None
    
    def _is_soft_404(self, response: ResponseWrapper) -> bool:
        """Detect soft 404 pages that return 200 but are actually 404s."""
        # Compare with baseline 404
        if self._baseline_404:
            # Check content length similarity
            baseline_len = self._baseline_404.content_length
            response_len = response.content_length
            
            # If lengths are very similar, likely soft 404
            if abs(baseline_len - response_len) < 50:
                return True
            
            # Check for 404 patterns
            body_lower = response.text.lower()
            for pattern in self._baseline_404_patterns:
                if pattern in body_lower:
                    return True
        
        # Additional soft 404 detection
        body_lower = response.text.lower()
        soft_404_indicators = [
            'not found',
            'page not found',
            'does not exist',
            '404',
            'error',
            'no results',
        ]
        
        # If multiple indicators and response is small, likely soft 404
        matches = sum(1 for ind in soft_404_indicators if ind in body_lower)
        if matches >= 2 and response.content_length < 5000:
            return True
        
        return False
    
    def _has_interesting_content(self, response: ResponseWrapper) -> bool:
        """Check if response contains interesting information."""
        body = response.text.lower()
        
        interesting_patterns = [
            'password',
            'secret',
            'api_key',
            'apikey',
            'access_token',
            'private_key',
            'database',
            'mongodb://',
            'mysql://',
            'postgresql://',
            'BEGIN RSA PRIVATE KEY',
            'BEGIN OPENSSH PRIVATE KEY',
        ]
        
        for pattern in interesting_patterns:
            if pattern.lower() in body:
                return True
        
        return False
    
    def _create_finding_from_result(
        self,
        result: DirectoryResult,
        base_url: str
    ) -> Finding:
        """Create a Finding from DirectoryResult."""
        full_url = f"{base_url}{result.path}"
        
        # Determine severity based on what was found
        severity = "info"
        
        # Elevate severity for sensitive paths
        sensitive_patterns = [
            ('.git', 'high'),
            ('.svn', 'high'),
            ('.env', 'high'),
            ('backup', 'medium'),
            ('config', 'medium'),
            ('admin', 'low'),
            ('phpmyadmin', 'medium'),
            ('wp-admin', 'low'),
            ('.htpasswd', 'high'),
            ('database', 'high'),
        ]
        
        for pattern, sev in sensitive_patterns:
            if pattern in result.path.lower():
                severity = sev
                break
        
        if result.status_code in self.AUTH_CODES:
            severity = max(severity, "low", key=lambda x: ["info", "low", "medium", "high", "critical"].index(x))
        
        return self.create_finding(
            vulnerability_type="Directory/File Found",
            url=full_url,
            severity=severity,
            confidence=90.0,
            evidence=(
                f"Path: {result.path}\n"
                f"Status Code: {result.status_code}\n"
                f"Content Length: {result.content_length}\n"
                f"Content Type: {result.content_type or 'N/A'}\n"
                f"Redirect: {result.redirect_url or 'N/A'}\n"
                f"Reason: {result.reason}"
            ),
            description=(
                f"The path '{result.path}' was discovered on the server. "
                f"{result.reason}"
            ),
            remediation=(
                "Review all discovered paths and ensure they should be publicly "
                "accessible. Remove or restrict access to sensitive files and "
                "directories. Implement proper access controls and consider "
                "using a Web Application Firewall (WAF)."
            ),
        )