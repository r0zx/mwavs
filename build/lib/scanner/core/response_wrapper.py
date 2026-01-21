"""
Response wrapper for standardized response handling.
Provides consistent response analysis and inspection capabilities.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple
from urllib.parse import urlparse
import hashlib
import re
import json
from datetime import datetime
import gzip
import zlib
from html.parser import HTMLParser
from io import StringIO

from .logger import get_logger

logger = get_logger("response")


class HTMLStripper(HTMLParser):
    """Simple HTML tag stripper."""
    
    def __init__(self):
        super().__init__()
        self.reset()
        self.strict = False
        self.convert_charrefs = True
        self.text = StringIO()
    
    def handle_data(self, data):
        self.text.write(data)
    
    def get_data(self):
        return self.text.getvalue()


@dataclass
class ResponseWrapper:
    """
    Wrapper for HTTP responses with analysis utilities.
    """
    status_code: int
    headers: Dict[str, str]
    body: bytes
    url: str
    elapsed_time: float  # seconds
    request_fingerprint: str
    
    # Optional fields
    redirect_history: List[str] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error: Optional[str] = None
    
    # Cached computed properties
    _text: Optional[str] = field(default=None, repr=False)
    _json: Optional[Dict] = field(default=None, repr=False)
    _body_hash: Optional[str] = field(default=None, repr=False)
    
    @property
    def text(self) -> str:
        """Get response body as text."""
        if self._text is None:
            # Try to detect encoding from headers
            encoding = self._detect_encoding()
            try:
                object.__setattr__(self, "_text", self.body.decode(encoding))
            except (UnicodeDecodeError, LookupError):
                # Fallback to latin-1 which accepts any byte
                object.__setattr__(self, "_text", self.body.decode("latin-1"))
        return self._text

    def _detect_encoding(self) -> str:
        """Detect character encoding from headers or content."""
        content_type = self.get_header("content-type", "")
        
        # Check Content-Type header
        match = re.search(r"charset=([^\s;]+)", content_type, re.I)
        if match:
            return match.group(1).strip("\"'")
        
        # Check for BOM
        if self.body.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
        elif self.body.startswith(b"\xff\xfe"):
            return "utf-16-le"
        elif self.body.startswith(b"\xfe\xff"):
            return "utf-16-be"
        
        # Check meta tag
        try:
            head = self.body[:1024].decode("ascii", errors="ignore")
            match = re.search(r'<meta[^>]+charset=["\']?([^"\'\s>]+)', head, re.I)
            if match:
                return match.group(1)
        except Exception:
            pass
        
        return "utf-8"
    
    @property
    def json(self) -> Optional[Dict]:
        """Parse response body as JSON."""
        if self._json is None:
            try:
                object.__setattr__(self, "_json", json.loads(self.text))
            except json.JSONDecodeError:
                return None
        return self._json
    
    @property
    def body_hash(self) -> str:
        """Get SHA256 hash of response body."""
        if self._body_hash is None:
            object.__setattr__(
                self, "_body_hash",
                hashlib.sha256(self.body).hexdigest()
            )
        return self._body_hash
    
    @property
    def content_length(self) -> int:
        """Get response body length."""
        return len(self.body)
    
    @property
    def content_type(self) -> Optional[str]:
        """Get Content-Type header."""
        return self.get_header("content-type")
    
    @property
    def is_html(self) -> bool:
        """Check if response is HTML."""
        ct = self.content_type or ""
        return "text/html" in ct.lower()
    
    @property
    def is_json(self) -> bool:
        """Check if response is JSON."""
        ct = self.content_type or ""
        return "application/json" in ct.lower() or "text/json" in ct.lower()
    
    @property
    def is_xml(self) -> bool:
        """Check if response is XML."""
        ct = self.content_type or ""
        return "xml" in ct.lower()
    
    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect."""
        return 300 <= self.status_code < 400
    
    @property
    def is_success(self) -> bool:
        """Check if response is successful."""
        return 200 <= self.status_code < 300
    
    @property
    def is_client_error(self) -> bool:
        """Check if response is a client error."""
        return 400 <= self.status_code < 500
    
    @property
    def is_server_error(self) -> bool:
        """Check if response is a server error."""
        return self.status_code >= 500
    
    @property
    def location(self) -> Optional[str]:
        """Get Location header for redirects."""
        return self.get_header("location")
    
    def get_header(
        self,
        name: str,
        default: Optional[str] = None
    ) -> Optional[str]:
        """Get header value (case-insensitive)."""
        name_lower = name.lower()
        for key, value in self.headers.items():
            if key.lower() == name_lower:
                return value
        return default
    
    def has_header(self, name: str) -> bool:
        """Check if header exists (case-insensitive)."""
        return self.get_header(name) is not None
    
    def contains(self, needle: str, case_sensitive: bool = False) -> bool:
        """Check if response body contains a string."""
        text = self.text
        if not case_sensitive:
            text = text.lower()
            needle = needle.lower()
        return needle in text
    
    def contains_any(
        self,
        needles: List[str],
        case_sensitive: bool = False
    ) -> Optional[str]:
        """Check if response contains any of the given strings."""
        for needle in needles:
            if self.contains(needle, case_sensitive):
                return needle
        return None
    
    def contains_all(
        self,
        needles: List[str],
        case_sensitive: bool = False
    ) -> bool:
        """Check if response contains all given strings."""
        return all(self.contains(n, case_sensitive) for n in needles)
    
    def regex_search(
        self,
        pattern: str,
        flags: int = 0
    ) -> Optional[re.Match]:
        """Search for regex pattern in response body."""
        return re.search(pattern, self.text, flags)
    
    def regex_find_all(
        self,
        pattern: str,
        flags: int = 0
    ) -> List[str]:
        """Find all matches for regex pattern."""
        return re.findall(pattern, self.text, flags)
    
    def extract_forms(self) -> List[Dict[str, Any]]:
        """Extract HTML forms from response."""
        forms = []
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.DOTALL | re.IGNORECASE
        )
        input_pattern = re.compile(
            r'<input[^>]*>',
            re.IGNORECASE
        )
        
        for form_match in form_pattern.finditer(self.text):
            form_html = form_match.group(0)
            form_data = {
                "action": self._extract_attr(form_html, "action"),
                "method": self._extract_attr(form_html, "method", "get").upper(),
                "inputs": [],
            }
            
            for input_match in input_pattern.finditer(form_match.group(1)):
                input_html = input_match.group(0)
                input_data = {
                    "name": self._extract_attr(input_html, "name"),
                    "type": self._extract_attr(input_html, "type", "text"),
                    "value": self._extract_attr(input_html, "value", ""),
                }
                if input_data["name"]:
                    form_data["inputs"].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def extract_links(self) -> List[str]:
        """Extract all links from response."""
        links = []
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            links.extend(re.findall(pattern, self.text, re.IGNORECASE))
        
        return list(set(links))
    
    def extract_comments(self) -> List[str]:
        """Extract HTML comments."""
        return re.findall(r'<!--(.*?)-->', self.text, re.DOTALL)
    
    def extract_scripts(self) -> List[str]:
        """Extract inline JavaScript."""
        pattern = re.compile(
            r'<script[^>]*>(.*?)</script>',
            re.DOTALL | re.IGNORECASE
        )
        return [m.group(1).strip() for m in pattern.finditer(self.text)]
    
    def strip_html(self) -> str:
        """Get text content without HTML tags."""
        stripper = HTMLStripper()
        stripper.feed(self.text)
        return stripper.get_data()
    
    def _extract_attr(
        self,
        html: str,
        attr: str,
        default: str = ""
    ) -> str:
        """Extract attribute value from HTML tag."""
        pattern = rf'{attr}=["\']([^"\']*)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Try without quotes
        pattern = rf'{attr}=([^\s>]+)'
        match = re.search(pattern, html, re.IGNORECASE)
        return match.group(1) if match else default
    
    def find_reflection(self, payload: str) -> List[Dict[str, Any]]:
        """
        Find where a payload is reflected in the response.
        Returns list of reflection contexts.
        """
        reflections = []
        text = self.text
        
        # Find all occurrences
        start = 0
        while True:
            idx = text.find(payload, start)
            if idx == -1:
                break
            
            # Determine context
            context = self._analyze_reflection_context(text, idx, payload)
            reflections.append({
                "position": idx,
                "context": context,
                "snippet": text[max(0, idx-50):idx+len(payload)+50],
            })
            
            start = idx + 1
        
        return reflections
    
    def _analyze_reflection_context(
        self,
        text: str,
        position: int,
        payload: str
    ) -> str:
        """Analyze the context of a reflection."""
        # Look at surrounding content
        before = text[max(0, position-100):position]
        after = text[position+len(payload):position+len(payload)+100]
        
        # Check if inside HTML tag attribute
        if re.search(r'<[^>]+=["\'][^"\']*$', before):
            return "html_attribute"
        
        # Check if inside HTML tag
        if re.search(r'<[^>]+$', before) and not re.search(r'>', before[-20:]):
            return "html_tag"
        
        # Check if inside script tag
        if re.search(r'<script[^>]*>[^<]*$', before, re.IGNORECASE):
            return "javascript"
        
        # Check if inside style tag
        if re.search(r'<style[^>]*>[^<]*$', before, re.IGNORECASE):
            return "css"
        
        # Check if inside HTML comment
        if '<!--' in before and '-->' not in before.split('<!--')[-1]:
            return "html_comment"
        
        return "html_body"
    
    def compare_to(
        self,
        other: "ResponseWrapper"
    ) -> Dict[str, Any]:
        """Compare this response to another."""
        return {
            "same_status": self.status_code == other.status_code,
            "status_diff": self.status_code - other.status_code,
            "same_length": self.content_length == other.content_length,
            "length_diff": self.content_length - other.content_length,
            "length_ratio": (
                self.content_length / other.content_length
                if other.content_length > 0 else 0
            ),
            "same_hash": self.body_hash == other.body_hash,
            "time_diff": self.elapsed_time - other.elapsed_time,
        }
    
    def to_raw_http(self) -> str:
        """Generate raw HTTP response string."""
        lines = [f"HTTP/1.1 {self.status_code}"]
        
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        
        lines.append("")
        lines.append(self.text[:5000])  # Truncate large bodies
        
        return "\r\n".join(lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "body_length": self.content_length,
            "body_hash": self.body_hash,
            "url": self.url,
            "elapsed_time": self.elapsed_time,
            "redirect_history": self.redirect_history,
            "cookies": dict(self.cookies),
            "timestamp": self.timestamp.isoformat(),
            "content_type": self.content_type,
        }


@dataclass
class ResponseDiff:
    """Represents differences between two responses."""
    response_a: ResponseWrapper
    response_b: ResponseWrapper
    
    @property
    def status_changed(self) -> bool:
        """Check if status code changed."""
        return self.response_a.status_code != self.response_b.status_code
    
    @property
    def length_diff(self) -> int:
        """Get difference in content length."""
        return self.response_b.content_length - self.response_a.content_length
    
    @property
    def length_diff_ratio(self) -> float:
        """Get ratio of length difference."""
        if self.response_a.content_length == 0:
            return float('inf') if self.response_b.content_length > 0 else 0
        return abs(self.length_diff) / self.response_a.content_length
    
    @property
    def time_diff(self) -> float:
        """Get difference in response time."""
        return self.response_b.elapsed_time - self.response_a.elapsed_time
    
    @property
    def headers_diff(self) -> Dict[str, Tuple[Optional[str], Optional[str]]]:
        """Get header differences."""
        all_headers = set(self.response_a.headers.keys()) | set(self.response_b.headers.keys())
        diff = {}
        
        for header in all_headers:
            val_a = self.response_a.get_header(header)
            val_b = self.response_b.get_header(header)
            if val_a != val_b:
                diff[header] = (val_a, val_b)
        
        return diff
    
    def is_significant(
        self,
        length_threshold: float = 0.1,
        time_threshold: float = 5.0
    ) -> bool:
        """
        Check if the difference is significant.
        
        Args:
            length_threshold: Minimum ratio for significant length change
            time_threshold: Minimum time difference (seconds) for significance
        """
        if self.status_changed:
            return True
        
        if self.length_diff_ratio > length_threshold:
            return True
        
        if abs(self.time_diff) > time_threshold:
            return True
        
        return False