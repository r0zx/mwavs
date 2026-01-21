"""
Utility functions and classes for the scanner.
Provides URL manipulation, payload encoding, response analysis, and more.
"""

import re
import html
import base64
import hashlib
import random
import string
import urllib.parse
from typing import Optional, Dict, List, Any, Tuple, Set, Generator
from dataclasses import dataclass
from pathlib import Path
from functools import lru_cache
import difflib
import unicodedata

from .logger import get_logger
from .exceptions import ValidationException

logger = get_logger("utils")


class URLUtils:
    """URL manipulation and validation utilities."""
    
    # Common file extensions to identify static resources
    STATIC_EXTENSIONS = {
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.mp4',
        '.mp3', '.pdf', '.zip', '.rar', '.gz', '.tar'
    }
    
    @staticmethod
    def normalize(url: str) -> str:
        """
        Normalize a URL to a canonical form.
        - Lowercase scheme and host
        - Remove default ports
        - Normalize path
        - Sort query parameters
        """
        parsed = urllib.parse.urlparse(url)
        
        # Lowercase scheme and netloc
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Remove default ports
        if netloc.endswith(':80') and scheme == 'http':
            netloc = netloc[:-3]
        elif netloc.endswith(':443') and scheme == 'https':
            netloc = netloc[:-4]
        
        # Normalize path
        path = parsed.path or '/'
        # Remove duplicate slashes
        path = re.sub(r'/+', '/', path)
        # Remove trailing slash (except for root)
        if path != '/' and path.endswith('/'):
            path = path[:-1]
        
        # Sort query parameters
        query_params = urllib.parse.parse_qsl(parsed.query)
        sorted_query = urllib.parse.urlencode(sorted(query_params))
        
        # Reconstruct URL
        return urllib.parse.urlunparse((
            scheme, netloc, path, '', sorted_query, ''
        ))
    
    @staticmethod
    def is_valid(url: str) -> bool:
        """Validate URL format."""
        try:
            parsed = urllib.parse.urlparse(url)
            return all([
                parsed.scheme in ('http', 'https'),
                parsed.netloc,
                '.' in parsed.netloc or parsed.netloc == 'localhost'
            ])
        except Exception:
            return False
    
    @staticmethod
    def get_domain(url: str) -> str:
        """Extract domain from URL."""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(':')[0]
    
    @staticmethod
    def get_base_url(url: str) -> str:
        """Get URL without path, query, or fragment."""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    @staticmethod
    def get_path(url: str) -> str:
        """Get path from URL."""
        return urllib.parse.urlparse(url).path or '/'
    
    @staticmethod
    def get_query_params(url: str) -> Dict[str, List[str]]:
        """Extract query parameters from URL."""
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.parse_qs(parsed.query)
    
    @staticmethod
    def set_query_params(url: str, params: Dict[str, str]) -> str:
        """Set or replace query parameters in URL."""
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.urlencode(params)
        return urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            '', query, ''
        ))
    
    @staticmethod
    def add_query_param(url: str, key: str, value: str) -> str:
        """Add a query parameter to URL."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[key] = [value]
        query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            '', query, ''
        ))
    
    @staticmethod
    def join(base: str, path: str) -> str:
        """Join base URL with path."""
        return urllib.parse.urljoin(base, path)
    
    @staticmethod
    def is_same_origin(url1: str, url2: str) -> bool:
        """Check if two URLs have the same origin."""
        p1 = urllib.parse.urlparse(url1)
        p2 = urllib.parse.urlparse(url2)
        return (p1.scheme == p2.scheme and p1.netloc == p2.netloc)
    
    @staticmethod
    def is_static_resource(url: str) -> bool:
        """Check if URL points to a static resource."""
        path = urllib.parse.urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in URLUtils.STATIC_EXTENSIONS)
    
    @staticmethod
    def extract_parameters(url: str) -> List[Tuple[str, str, str]]:
        """
        Extract all injectable parameters from URL.
        Returns list of (location, name, value) tuples.
        """
        params = []
        parsed = urllib.parse.urlparse(url)
        
        # Query parameters
        for key, values in urllib.parse.parse_qs(parsed.query).items():
            for value in values:
                params.append(('query', key, value))
        
        # Path parameters (numeric segments, UUIDs, etc.)
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            if part and (part.isdigit() or URLUtils._looks_like_id(part)):
                params.append(('path', f'path_{i}', part))
        
        return params
    
    @staticmethod
    def _looks_like_id(value: str) -> bool:
        """Check if value looks like an ID parameter."""
        # UUID pattern
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return True
        # Hex string (like MongoDB ObjectId)
        if re.match(r'^[0-9a-f]{24}$', value, re.I):
            return True
        # Base64-like
        if re.match(r'^[A-Za-z0-9+/=]{20,}$', value):
            return True
        return False


class PayloadEncoder:
    """Payload encoding utilities for various contexts."""
    
    @staticmethod
    def url_encode(payload: str, safe: str = '') -> str:
        """URL encode a payload."""
        return urllib.parse.quote(payload, safe=safe)
    
    @staticmethod
    def url_encode_all(payload: str) -> str:
        """URL encode all characters."""
        return ''.join(f'%{ord(c):02X}' for c in payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode a payload."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    @staticmethod
    def html_encode(payload: str) -> str:
        """HTML entity encode a payload."""
        return html.escape(payload)
    
    @staticmethod
    def html_encode_numeric(payload: str) -> str:
        """HTML numeric entity encode."""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def html_encode_hex(payload: str) -> str:
        """HTML hex entity encode."""
        return ''.join(f'&#x{ord(c):x};' for c in payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode a payload."""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def base64_decode(payload: str) -> str:
        """Base64 decode a payload."""
        try:
            return base64.b64decode(payload).decode()
        except Exception:
            return payload
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode escape encode."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode a payload."""
        return payload.encode().hex()
    
    @staticmethod
    def javascript_encode(payload: str) -> str:
        """JavaScript string encode."""
        result = []
        for char in payload:
            if char in '\'"\\':
                result.append(f'\\{char}')
            elif char == '\n':
                result.append('\\n')
            elif char == '\r':
                result.append('\\r')
            elif char == '\t':
                result.append('\\t')
            elif ord(char) < 32 or ord(char) > 126:
                result.append(f'\\x{ord(char):02x}')
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def sql_char_encode(payload: str) -> str:
        """SQL CHAR() encode for bypass."""
        return 'CHAR(' + ','.join(str(ord(c)) for c in payload) + ')'
    
    @staticmethod
    def case_variation(payload: str) -> str:
        """Random case variation for bypass."""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
    
    @staticmethod
    def null_byte_inject(payload: str) -> str:
        """Add null byte for bypass attempts."""
        return payload + '%00'
    
    @staticmethod
    def get_all_encodings(payload: str) -> Dict[str, str]:
        """Get all encoding variations of a payload."""
        return {
            'original': payload,
            'url_encoded': PayloadEncoder.url_encode(payload),
            'double_url': PayloadEncoder.double_url_encode(payload),
            'html_encoded': PayloadEncoder.html_encode(payload),
            'html_numeric': PayloadEncoder.html_encode_numeric(payload),
            'base64': PayloadEncoder.base64_encode(payload),
            'unicode': PayloadEncoder.unicode_encode(payload),
        }


class ResponseAnalyzer:
    """Utilities for analyzing HTTP responses."""
    
    # Common error patterns
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB)",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
        r"MySqlException",
        r"SQLSTATE\[\d+\]",
        r"ORA-\d{5}",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"oracle\.jdbc\.driver",
        r"quoted string not properly terminated",
        r"Microsoft.*ODBC.*Driver",
        r"Microsoft.*SQL.*Server",
        r"SQLServer JDBC Driver",
        r"SqlException",
        r"Unclosed quotation mark",
        r"mssql_query\(\)",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"SQLite.*(?:Error|Exception)",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"SQLITE_ERROR",
        r"sqlite3\.OperationalError",
    ]
    
    WAF_SIGNATURES = {
        'cloudflare': [
            'cloudflare', 'cf-ray', '__cfduid', 'cf-request-id'
        ],
        'akamai': [
            'akamai', 'akamai-ghost', 'x-akamai'
        ],
        'aws_waf': [
            'awswaf', 'x-amzn-requestid', 'x-amz-cf-id'
        ],
        'imperva': [
            'incapsula', 'imperva', 'visid_incap'
        ],
        'f5_bigip': [
            'bigip', 'f5', 'ts=', 'bigipserver'
        ],
        'modsecurity': [
            'modsecurity', 'mod_security', 'owasp'
        ],
        'sucuri': [
            'sucuri', 'x-sucuri'
        ],
    }
    
    @classmethod
    def detect_sql_error(cls, response_text: str) -> Optional[Tuple[str, str]]:
        """
        Detect SQL error messages in response.
        Returns (pattern, matched_text) or None.
        """
        for pattern in cls.SQL_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return (pattern, match.group(0))
        return None
    
    @classmethod
    def detect_waf(cls, headers: Dict[str, str], body: str) -> Optional[str]:
        """Detect WAF presence from headers and body."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()
        
        for waf_name, signatures in cls.WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                # Check headers
                for key, value in headers_lower.items():
                    if sig_lower in key or sig_lower in value:
                        return waf_name
                # Check body
                if sig_lower in body_lower:
                    return waf_name
        
        # Check for generic WAF blocking patterns
        block_patterns = [
            r'access denied',
            r'blocked',
            r'forbidden',
            r'not acceptable',
            r'request rejected',
            r'security violation',
            r'suspicious activity',
        ]
        
        for pattern in block_patterns:
            if re.search(pattern, body_lower):
                # Might be WAF, return generic
                return 'unknown'
        
        return None
    
    @staticmethod
    def calculate_similarity(text1: str, text2: str) -> float:
        """
        Calculate similarity ratio between two texts.
        Returns value between 0 and 1.
        """
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        
        # Use difflib for sequence matching
        matcher = difflib.SequenceMatcher(None, text1, text2)
        return matcher.ratio()
    
    @staticmethod
    def extract_error_context(
        response_text: str,
        error_pattern: str,
        context_size: int = 200
    ) -> Optional[str]:
        """Extract context around an error pattern."""
        match = re.search(error_pattern, response_text, re.IGNORECASE)
        if not match:
            return None
        
        start = max(0, match.start() - context_size)
        end = min(len(response_text), match.end() + context_size)
        
        context = response_text[start:end]
        # Clean up for display
        context = re.sub(r'\s+', ' ', context)
        
        return context
    
    @staticmethod
    def detect_technology(
        headers: Dict[str, str],
        body: str
    ) -> Dict[str, List[str]]:
        """Detect web technologies from response."""
        tech = {
            'server': [],
            'framework': [],
            'language': [],
            'cms': [],
            'frontend': [],
        }
        
        # Server detection
        server = headers.get('Server', headers.get('server', ''))
        if server:
            tech['server'].append(server)
        
        x_powered = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
        if x_powered:
            if 'php' in x_powered.lower():
                tech['language'].append('PHP')
            elif 'asp' in x_powered.lower():
                tech['language'].append('ASP.NET')
            tech['framework'].append(x_powered)
        
        # Framework detection from body
        framework_patterns = {
            'wordpress': (r'wp-content|wp-includes|wordpress', 'cms'),
            'drupal': (r'drupal|sites/all|sites/default', 'cms'),
            'joomla': (r'joomla|/components/com_', 'cms'),
            'django': (r'csrfmiddlewaretoken|django', 'framework'),
            'rails': (r'rails|ruby', 'framework'),
            'laravel': (r'laravel|illuminate', 'framework'),
            'react': (r'react|_reactRoot', 'frontend'),
            'angular': (r'ng-app|angular|ng-', 'frontend'),
            'vue': (r'vue\.js|v-bind|v-model', 'frontend'),
            'jquery': (r'jquery', 'frontend'),
        }
        
        for name, (pattern, category) in framework_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                tech[category].append(name)
        
        return tech
    
    @staticmethod
    def is_error_page(status_code: int, body: str) -> bool:
        """Detect if response is an error page."""
        if status_code >= 400:
            return True
        
        error_indicators = [
            r'error',
            r'exception',
            r'not found',
            r'access denied',
            r'forbidden',
            r'internal server error',
            r'service unavailable',
        ]
        
        body_lower = body.lower()
        for indicator in error_indicators:
            if re.search(rf'\b{indicator}\b', body_lower):
                # Check if it's in a significant context (title, h1, etc.)
                if re.search(rf'<(title|h1|h2)[^>]*>.*?{indicator}', body_lower):
                    return True
        
        return False


class RandomUtils:
    """Random data generation utilities."""
    
    @staticmethod
    def string(length: int = 8, charset: str = None) -> str:
        """Generate random string."""
        if charset is None:
            charset = string.ascii_letters + string.digits
        return ''.join(random.choice(charset) for _ in range(length))
    
    @staticmethod
    def hex_string(length: int = 16) -> str:
        """Generate random hex string."""
        return ''.join(random.choice('0123456789abcdef') for _ in range(length))
    
    @staticmethod
    def email() -> str:
        """Generate random email."""
        return f"{RandomUtils.string(8)}@{RandomUtils.string(6)}.com"
    
    @staticmethod
    def user_agent() -> str:
        """Get random user agent."""
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
        return random.choice(agents)
    
    @staticmethod
    def boundary() -> str:
        """Generate multipart boundary."""
        return f"----WebKitFormBoundary{RandomUtils.string(16)}"


class PayloadManager:
    """Manages payload loading and iteration."""
    
    def __init__(self, payloads_dir: Path):
        self.payloads_dir = payloads_dir
        self._cache: Dict[str, List[str]] = {}
    
    def load(self, payload_type: str) -> List[str]:
        """Load payloads from file."""
        if payload_type in self._cache:
            return self._cache[payload_type]
        
        file_path = self.payloads_dir / f"{payload_type}.txt"
        
        if not file_path.exists():
            logger.warning(f"Payload file not found: {file_path}")
            return []
        
        payloads = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.append(line)
        
        self._cache[payload_type] = payloads
        logger.debug(f"Loaded {len(payloads)} payloads from {payload_type}")
        
        return payloads
    
    def get_variants(
        self,
        payload: str,
        encodings: bool = True
    ) -> Generator[Tuple[str, str], None, None]:
        """Generate payload variants with different encodings."""
        yield ('original', payload)
        
        if encodings:
            yield ('url_encoded', PayloadEncoder.url_encode(payload))
            yield ('double_url', PayloadEncoder.double_url_encode(payload))
            yield ('html_encoded', PayloadEncoder.html_encode(payload))
            yield ('case_varied', PayloadEncoder.case_variation(payload))


class WordlistManager:
    """Manages wordlist loading for enumeration."""
    
    def __init__(self, wordlists_dir: Path):
        self.wordlists_dir = wordlists_dir
        self._cache: Dict[str, List[str]] = {}
    
    def load(self, wordlist_name: str) -> List[str]:
        """Load wordlist from file."""
        if wordlist_name in self._cache:
            return self._cache[wordlist_name]
        
        file_path = self.wordlists_dir / f"{wordlist_name}.txt"
        
        if not file_path.exists():
            logger.warning(f"Wordlist not found: {file_path}")
            return []
        
        words = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith('#'):
                    words.append(word)
        
        self._cache[wordlist_name] = words
        logger.debug(f"Loaded {len(words)} words from {wordlist_name}")
        
        return words
    
    def iter_with_extensions(
        self,
        wordlist_name: str,
        extensions: List[str]
    ) -> Generator[str, None, None]:
        """Iterate wordlist with file extensions."""
        words = self.load(wordlist_name)
        
        for word in words:
            yield word
            for ext in extensions:
                if not ext.startswith('.'):
                    ext = '.' + ext
                yield word + ext


@dataclass
class Finding:
    """Represents a security finding."""
    plugin_name: str
    vulnerability_type: str
    severity: str  # critical, high, medium, low, info
    confidence: float  # 0-100
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    request_data: Optional[Dict] = None
    response_data: Optional[Dict] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
    
    @property
    def severity_score(self) -> int:
        """Get numeric severity score."""
        scores = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1,
        }
        return scores.get(self.severity.lower(), 0)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'plugin_name': self.plugin_name,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'evidence': self.evidence,
            'request_data': self.request_data,
            'response_data': self.response_data,
            'description': self.description,
            'remediation': self.remediation,
            'references': self.references,
        }


class RateLimiter:
    """Simple rate limiter for requests."""
    
    def __init__(self, requests_per_second: float):
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self._last_request = 0.0
        self._lock = __import__('threading').Lock()
    
    def wait(self):
        """Wait if necessary to respect rate limit."""
        import time
        
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request
            
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
            
            self._last_request = time.time()