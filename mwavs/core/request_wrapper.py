"""
Request wrapper for standardized request handling.
Provides immutable request representation with validation.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Union
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import hashlib
import json
import copy
from enum import Enum

from .exceptions import ValidationException
from .logger import get_logger

logger = get_logger("request")


class HTTPMethod(Enum):
    """Supported HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ContentType(Enum):
    """Common content types."""
    FORM = "application/x-www-form-urlencoded"
    JSON = "application/json"
    MULTIPART = "multipart/form-data"
    XML = "application/xml"
    TEXT = "text/plain"


@dataclass(frozen=True)
class RequestWrapper:
    """
    Immutable wrapper for HTTP requests.
    Provides standardized request representation and utilities.
    """
    url: str
    method: HTTPMethod = HTTPMethod.GET
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Union[str, List[str]]] = field(default_factory=dict)
    data: Optional[Union[str, Dict[str, Any]]] = None
    json_data: Optional[Dict[str, Any]] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0
    allow_redirects: bool = True
    verify_ssl: bool = True
    
    # Metadata
    tag: Optional[str] = None  # Custom tag for tracking
    context: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate request after creation."""
        self._validate_url()
        self._validate_method()

    def _validate_url(self):
        """Validate URL format."""
        parsed = urlparse(self.url)
        if not parsed.scheme or not parsed.netloc:
            raise ValidationException(
                f"Invalid URL format: {self.url}",
                field="url",
                value=self.url,
            )
        if parsed.scheme not in ("http", "https"):
            raise ValidationException(
                f"Unsupported URL scheme: {parsed.scheme}",
                field="url",
                value=self.url,
            )

    def _validate_method(self):
        """Validate HTTP method."""
        if not isinstance(self.method, HTTPMethod):
            raise ValidationException(
                f"Invalid HTTP method: {self.method}",
                field="method",
                value=self.method,
            )

    @property
    def parsed_url(self):
        """Get parsed URL components."""
        return urlparse(self.url)
    
    @property
    def base_url(self) -> str:
        """Get URL without query parameters."""
        parsed = self.parsed_url
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    
    @property
    def domain(self) -> str:
        """Get domain from URL."""
        return self.parsed_url.netloc
    
    @property
    def path(self) -> str:
        """Get path from URL."""
        return self.parsed_url.path or "/"
    
    @property
    def query_params(self) -> Dict[str, List[str]]:
        """Get query parameters from URL."""
        return parse_qs(self.parsed_url.query)
    
    @property
    def all_params(self) -> Dict[str, Union[str, List[str]]]:
        """Get all parameters (URL + explicit params)."""
        all_params = {}
        # URL query params
        for key, values in self.query_params.items():
            all_params[key] = values[0] if len(values) == 1 else values
        # Explicit params
        all_params.update(self.params)
        return all_params
    
    @property
    def content_type(self) -> Optional[str]:
        """Get Content-Type header."""
        for key, value in self.headers.items():
            if key.lower() == "content-type":
                return value
        return None
    
    @property
    def fingerprint(self) -> str:
        """Generate unique fingerprint for this request."""
        components = [
            self.method.value,
            self.base_url,
            json.dumps(sorted(self.params.items())),
            json.dumps(sorted(self.headers.items())),
        ]
        if self.data:
            if isinstance(self.data, dict):
                components.append(json.dumps(sorted(self.data.items())))
            else:
                components.append(str(self.data))
        if self.json_data:
            components.append(json.dumps(self.json_data, sort_keys=True))
        
        combined = "|".join(components)
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
    
    def with_param(self, key: str, value: str) -> "RequestWrapper":
        """Create new request with additional/modified parameter."""
        new_params = dict(self.params)
        new_params[key] = value
        return self._replace(params=new_params)
    
    def with_header(self, key: str, value: str) -> "RequestWrapper":
        """Create new request with additional/modified header."""
        new_headers = dict(self.headers)
        new_headers[key] = value
        return self._replace(headers=new_headers)
    
    def with_cookie(self, key: str, value: str) -> "RequestWrapper":
        """Create new request with additional/modified cookie."""
        new_cookies = dict(self.cookies)
        new_cookies[key] = value
        return self._replace(cookies=new_cookies)
    
    def with_url(self, url: str) -> "RequestWrapper":
        """Create new request with different URL."""
        return self._replace(url=url)
    
    def with_method(self, method: HTTPMethod) -> "RequestWrapper":
        """Create new request with different method."""
        return self._replace(method=method)
    
    def with_data(self, data: Union[str, Dict[str, Any]]) -> "RequestWrapper":
        """Create new request with modified data."""
        return self._replace(data=data)
    
    def with_tag(self, tag: str) -> "RequestWrapper":
        """Create new request with a tag for tracking."""
        return self._replace(tag=tag)
    
    def with_context(self, **kwargs) -> "RequestWrapper":
        """Create new request with additional context."""
        new_context = dict(self.context)
        new_context.update(kwargs)
        return self._replace(context=new_context)
    
    def _replace(self, **changes) -> "RequestWrapper":
        """Create a copy with specified changes."""
        # Convert frozen dataclass to dict
        current = {
            "url": self.url,
            "method": self.method,
            "headers": dict(self.headers),
            "params": dict(self.params),
            "data": self.data,
            "json_data": self.json_data,
            "cookies": dict(self.cookies),
            "timeout": self.timeout,
            "allow_redirects": self.allow_redirects,
            "verify_ssl": self.verify_ssl,
            "tag": self.tag,
            "context": dict(self.context),
        }
        current.update(changes)
        return RequestWrapper(**current)
    
    def build_full_url(self) -> str:
        """Build complete URL with all parameters."""
        if not self.params:
            return self.url
        
        parsed = self.parsed_url
        existing_params = parse_qs(parsed.query)
        
        # Merge parameters
        all_params = {}
        for key, value in existing_params.items():
            all_params[key] = value[0] if len(value) == 1 else value
        all_params.update(self.params)
        
        query_string = urlencode(all_params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query_string,
            parsed.fragment,
        ))
    
    def to_curl(self) -> str:
        """Generate equivalent curl command."""
        parts = [f"curl -X {self.method.value}"]
        
        for key, value in self.headers.items():
            parts.append(f"-H '{key}: {value}'")
        
        for key, value in self.cookies.items():
            parts.append(f"-b '{key}={value}'")
        
        if self.data:
            if isinstance(self.data, dict):
                data_str = urlencode(self.data)
            else:
                data_str = self.data
            parts.append(f"-d '{data_str}'")
        
        if self.json_data:
            parts.append(f"-d '{json.dumps(self.json_data)}'")
            parts.append("-H 'Content-Type: application/json'")
        
        if not self.verify_ssl:
            parts.append("-k")
        
        if not self.allow_redirects:
            parts.append("--max-redirs 0")
        
        parts.append(f"'{self.build_full_url()}'")
        
        return " \\\n  ".join(parts)
    
    def to_raw_http(self) -> str:
        """Generate raw HTTP request string."""
        parsed = self.parsed_url
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        if self.params:
            separator = "&" if parsed.query else "?"
            path += separator + urlencode(self.params)
        
        lines = [f"{self.method.value} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")
        
        for key, value in self.headers.items():
            if key.lower() != "host":
                lines.append(f"{key}: {value}")
        
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            lines.append(f"Cookie: {cookie_str}")
        
        body = ""
        if self.data:
            if isinstance(self.data, dict):
                body = urlencode(self.data)
                if "Content-Type" not in [k.lower() for k in self.headers]:
                    lines.append(f"Content-Type: {ContentType.FORM.value}")
            else:
                body = str(self.data)
            lines.append(f"Content-Length: {len(body)}")
        elif self.json_data:
            body = json.dumps(self.json_data)
            if "Content-Type" not in [k.lower() for k in self.headers]:
                lines.append("Content-Type: application/json")
            lines.append(f"Content-Length: {len(body)}")
        
        lines.append("")  # Empty line before body
        if body:
            lines.append(body)
        
        return "\r\n".join(lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "url": self.url,
            "method": self.method.value,
            "headers": dict(self.headers),
            "params": dict(self.params),
            "data": self.data,
            "json_data": self.json_data,
            "cookies": dict(self.cookies),
            "timeout": self.timeout,
            "allow_redirects": self.allow_redirects,
            "verify_ssl": self.verify_ssl,
            "tag": self.tag,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RequestWrapper":
        """Create from dictionary."""
        if "method" in data and isinstance(data["method"], str):
            data["method"] = HTTPMethod(data["method"])
        return cls(**data)


class RequestBuilder:
    """
    Fluent builder for constructing RequestWrapper instances.
    """
    
    def __init__(self, url: str):
        self._url = url
        self._method = HTTPMethod.GET
        self._headers: Dict[str, str] = {}
        self._params: Dict[str, str] = {}
        self._data: Optional[Union[str, Dict]] = None
        self._json_data: Optional[Dict] = None
        self._cookies: Dict[str, str] = {}
        self._timeout = 30.0
        self._allow_redirects = True
        self._verify_ssl = True
        self._tag: Optional[str] = None
        self._context: Dict[str, Any] = {}
    
    def method(self, method: Union[str, HTTPMethod]) -> "RequestBuilder":
        """Set HTTP method."""
        if isinstance(method, str):
            method = HTTPMethod(method.upper())
        self._method = method
        return self
    
    def get(self) -> "RequestBuilder":
        """Set method to GET."""
        return self.method(HTTPMethod.GET)
    
    def post(self) -> "RequestBuilder":
        """Set method to POST."""
        return self.method(HTTPMethod.POST)
    
    def put(self) -> "RequestBuilder":
        """Set method to PUT."""
        return self.method(HTTPMethod.PUT)
    
    def delete(self) -> "RequestBuilder":
        """Set method to DELETE."""
        return self.method(HTTPMethod.DELETE)
    
    def header(self, key: str, value: str) -> "RequestBuilder":
        """Add header."""
        self._headers[key] = value
        return self
    
    def headers(self, headers: Dict[str, str]) -> "RequestBuilder":
        """Add multiple headers."""
        self._headers.update(headers)
        return self
    
    def param(self, key: str, value: str) -> "RequestBuilder":
        """Add query parameter."""
        self._params[key] = value
        return self
    
    def params(self, params: Dict[str, str]) -> "RequestBuilder":
        """Add multiple query parameters."""
        self._params.update(params)
        return self
    
    def data(self, data: Union[str, Dict]) -> "RequestBuilder":
        """Set request body data."""
        self._data = data
        return self
    
    def json(self, data: Dict) -> "RequestBuilder":
        """Set JSON request body."""
        self._json_data = data
        return self
    
    def cookie(self, key: str, value: str) -> "RequestBuilder":
        """Add cookie."""
        self._cookies[key] = value
        return self
    
    def cookies(self, cookies: Dict[str, str]) -> "RequestBuilder":
        """Add multiple cookies."""
        self._cookies.update(cookies)
        return self
    
    def timeout(self, timeout: float) -> "RequestBuilder":
        """Set request timeout."""
        self._timeout = timeout
        return self
    
    def no_redirects(self) -> "RequestBuilder":
        """Disable following redirects."""
        self._allow_redirects = False
        return self
    
    def insecure(self) -> "RequestBuilder":
        """Disable SSL verification."""
        self._verify_ssl = False
        return self
    
    def tag(self, tag: str) -> "RequestBuilder":
        """Set request tag."""
        self._tag = tag
        return self
    
    def context(self, **kwargs) -> "RequestBuilder":
        """Add context data."""
        self._context.update(kwargs)
        return self
    
    def build(self) -> RequestWrapper:
        """Build the RequestWrapper instance."""
        return RequestWrapper(
            url=self._url,
            method=self._method,
            headers=self._headers,
            params=self._params,
            data=self._data,
            json_data=self._json_data,
            cookies=self._cookies,
            timeout=self._timeout,
            allow_redirects=self._allow_redirects,
            verify_ssl=self._verify_ssl,
            tag=self._tag,
            context=self._context,
        )