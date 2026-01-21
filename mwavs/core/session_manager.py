"""
Session management for maintaining state across requests.
Handles cookies, authentication, and session persistence.
"""

import json
import pickle
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
import threading
import http.cookiejar
from urllib.parse import urlparse

from .logger import get_logger
from .exceptions import ScannerException

logger = get_logger("session")


@dataclass
class Cookie:
    """Represents a single cookie."""
    name: str
    value: str
    domain: str
    path: str = "/"
    expires: Optional[datetime] = None
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    
    @property
    def is_expired(self) -> bool:
        """Check if cookie is expired."""
        if self.expires is None:
            return False
        return datetime.utcnow() > self.expires
    
    def matches_domain(self, domain: str) -> bool:
        """Check if cookie matches a domain."""
        if self.domain.startswith("."):
            return domain.endswith(self.domain) or domain == self.domain[1:]
        return domain == self.domain
    
    def matches_path(self, path: str) -> bool:
        """Check if cookie matches a path."""
        return path.startswith(self.path)
    
    def to_header_value(self) -> str:
        """Convert to Cookie header format."""
        return f"{self.name}={self.value}"


class CookieJar:
    """Thread-safe cookie storage."""
    
    def __init__(self):
        self._cookies: Dict[str, Dict[str, Cookie]] = {}
        self._lock = threading.RLock()
    
    def set(self, cookie: Cookie) -> None:
        """Add or update a cookie."""
        with self._lock:
            domain_key = cookie.domain.lstrip(".")
            if domain_key not in self._cookies:
                self._cookies[domain_key] = {}
            
            cookie_key = f"{cookie.name}:{cookie.path}"
            self._cookies[domain_key][cookie_key] = cookie
            
            logger.debug(
                f"Cookie set: {cookie.name}={cookie.value[:20]}... "
                f"for {cookie.domain}"
            )
    
    def get(self, name: str, domain: str) -> Optional[Cookie]:
        """Get a specific cookie."""
        with self._lock:
            domain_key = domain.lstrip(".")
            domain_cookies = self._cookies.get(domain_key, {})
            
            for cookie_key, cookie in domain_cookies.items():
                if cookie.name == name and not cookie.is_expired:
                    return cookie
            
            return None
    
    def get_for_url(self, url: str) -> List[Cookie]:
        """Get all cookies applicable to a URL."""
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]  # Remove port
        path = parsed.path or "/"
        is_secure = parsed.scheme == "https"
        
        applicable = []
        
        with self._lock:
            for domain_key, domain_cookies in self._cookies.items():
                for cookie in domain_cookies.values():
                    if cookie.is_expired:
                        continue
                    
                    if not cookie.matches_domain(domain):
                        continue
                    
                    if not cookie.matches_path(path):
                        continue
                    
                    if cookie.secure and not is_secure:
                        continue
                    
                    applicable.append(cookie)
        
        return applicable
    
    def get_header_value(self, url: str) -> Optional[str]:
        """Get Cookie header value for a URL."""
        cookies = self.get_for_url(url)
        if not cookies:
            return None
        
        return "; ".join(c.to_header_value() for c in cookies)
    
    def set_from_header(
        self,
        header_value: str,
        domain: str,
        path: str = "/"
    ) -> None:
        """Parse and set cookies from Set-Cookie header."""
        parts = header_value.split(";")
        
        if not parts:
            return
        
        # First part is name=value
        name_value = parts[0].strip()
        if "=" not in name_value:
            return
        
        name, value = name_value.split("=", 1)
        
        cookie = Cookie(
            name=name.strip(),
            value=value.strip(),
            domain=domain,
            path=path,
        )
        
        # Parse attributes
        for part in parts[1:]:
            part = part.strip()
            if "=" in part:
                attr_name, attr_value = part.split("=", 1)
                attr_name = attr_name.strip().lower()
                attr_value = attr_value.strip()
                
                if attr_name == "domain":
                    cookie.domain = attr_value
                elif attr_name == "path":
                    cookie.path = attr_value
                elif attr_name == "expires":
                    try:
                        cookie.expires = self._parse_expires(attr_value)
                    except ValueError:
                        pass
                elif attr_name == "max-age":
                    try:
                        seconds = int(attr_value)
                        cookie.expires = datetime.utcnow() + timedelta(seconds=seconds)
                    except ValueError:
                        pass
                elif attr_name == "samesite":
                    cookie.same_site = attr_value
            else:
                attr_name = part.lower()
                if attr_name == "secure":
                    cookie.secure = True
                elif attr_name == "httponly":
                    cookie.http_only = True
        
        self.set(cookie)
    
    def _parse_expires(self, value: str) -> datetime:
        """Parse cookie expires date."""
        formats = [
            "%a, %d %b %Y %H:%M:%S GMT",
            "%a, %d-%b-%Y %H:%M:%S GMT",
            "%a, %d %b %Y %H:%M:%S %z",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        
        raise ValueError(f"Cannot parse date: {value}")
    
    def clear(self, domain: Optional[str] = None) -> None:
        """Clear cookies."""
        with self._lock:
            if domain:
                domain_key = domain.lstrip(".")
                self._cookies.pop(domain_key, None)
            else:
                self._cookies.clear()
    
    def clear_expired(self) -> int:
        """Remove expired cookies."""
        removed = 0
        
        with self._lock:
            for domain_key in list(self._cookies.keys()):
                domain_cookies = self._cookies[domain_key]
                for cookie_key in list(domain_cookies.keys()):
                    if domain_cookies[cookie_key].is_expired:
                        del domain_cookies[cookie_key]
                        removed += 1
                
                if not domain_cookies:
                    del self._cookies[domain_key]
        
        return removed
    
    def to_dict(self) -> Dict[str, Any]:
        """Export cookies to dictionary."""
        with self._lock:
            result = {}
            for domain_key, domain_cookies in self._cookies.items():
                result[domain_key] = {
                    k: {
                        "name": c.name,
                        "value": c.value,
                        "domain": c.domain,
                        "path": c.path,
                        "expires": c.expires.isoformat() if c.expires else None,
                        "secure": c.secure,
                        "http_only": c.http_only,
                        "same_site": c.same_site,
                    }
                    for k, c in domain_cookies.items()
                }
            return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CookieJar":
        """Import cookies from dictionary."""
        jar = cls()
        
        for domain_key, domain_cookies in data.items():
            for cookie_key, cookie_data in domain_cookies.items():
                expires = None
                if cookie_data.get("expires"):
                    expires = datetime.fromisoformat(cookie_data["expires"])
                
                cookie = Cookie(
                    name=cookie_data["name"],
                    value=cookie_data["value"],
                    domain=cookie_data["domain"],
                    path=cookie_data.get("path", "/"),
                    expires=expires,
                    secure=cookie_data.get("secure", False),
                    http_only=cookie_data.get("http_only", False),
                    same_site=cookie_data.get("same_site"),
                )
                jar.set(cookie)
        
        return jar


@dataclass
class Session:
    """
    Represents a scanner session with persistent state.
    """
    id: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    cookie_jar: CookieJar = field(default_factory=CookieJar)
    auth_token: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_cookie(
        self,
        name: str,
        value: str,
        domain: str,
        **kwargs
    ) -> None:
        """Add a cookie to the session."""
        cookie = Cookie(name=name, value=value, domain=domain, **kwargs)
        self.cookie_jar.set(cookie)
    
    def set_auth_token(self, token: str, header_name: str = "Authorization"):
        """Set authentication token."""
        self.auth_token = token
        self.custom_headers[header_name] = token
    
    def get_headers(self, url: str) -> Dict[str, str]:
        """Get all headers for a request."""
        headers = dict(self.custom_headers)
        
        cookie_value = self.cookie_jar.get_header_value(url)
        if cookie_value:
            headers["Cookie"] = cookie_value
        
        return headers
    
    def update_from_response(
        self,
        response_headers: Dict[str, str],
        url: str
    ) -> None:
        """Update session state from response headers."""
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]
        path = parsed.path or "/"
        
        for key, value in response_headers.items():
            if key.lower() == "set-cookie":
                self.cookie_jar.set_from_header(value, domain, path)
    
    def to_dict(self) -> Dict[str, Any]:
        """Export session to dictionary."""
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "cookies": self.cookie_jar.to_dict(),
            "auth_token": self.auth_token,
            "custom_headers": self.custom_headers,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        """Import session from dictionary."""
        return cls(
            id=data["id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            cookie_jar=CookieJar.from_dict(data.get("cookies", {})),
            auth_token=data.get("auth_token"),
            custom_headers=data.get("custom_headers", {}),
            metadata=data.get("metadata", {}),
        )


class SessionManager:
    """
    Manages multiple sessions and their persistence.
    """
    
    def __init__(self, storage_path: Optional[Path] = None):
        self._sessions: Dict[str, Session] = {}
        self._active_session: Optional[str] = None
        self._storage_path = storage_path
        self._lock = threading.RLock()
        
        if storage_path and storage_path.exists():
            self._load_sessions()
    
    def create_session(self, session_id: Optional[str] = None) -> Session:
        """Create a new session."""
        import uuid
        
        with self._lock:
            if session_id is None:
                session_id = str(uuid.uuid4())[:8]
            
            if session_id in self._sessions:
                raise ScannerException(f"Session already exists: {session_id}")
            
            session = Session(id=session_id)
            self._sessions[session_id] = session
            
            if self._active_session is None:
                self._active_session = session_id
            
            logger.info(f"Created session: {session_id}")
            return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        return self._sessions.get(session_id)
    
    @property
    def active_session(self) -> Optional[Session]:
        """Get the currently active session."""
        if self._active_session:
            return self._sessions.get(self._active_session)
        return None
    
    def set_active_session(self, session_id: str) -> None:
        """Set the active session."""
        if session_id not in self._sessions:
            raise ScannerException(f"Session not found: {session_id}")
        self._active_session = session_id
    
    def delete_session(self, session_id: str) -> None:
        """Delete a session."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                
                if self._active_session == session_id:
                    self._active_session = (
                        next(iter(self._sessions)) if self._sessions else None
                    )
                
                logger.info(f"Deleted session: {session_id}")
    
    def list_sessions(self) -> List[str]:
        """List all session IDs."""
        return list(self._sessions.keys())
    
    def save_sessions(self) -> None:
        """Save all sessions to storage."""
        if not self._storage_path:
            return
        
        with self._lock:
            data = {
                "active_session": self._active_session,
                "sessions": {
                    sid: session.to_dict()
                    for sid, session in self._sessions.items()
                },
            }
            
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._storage_path, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Saved sessions to {self._storage_path}")
    
    def _load_sessions(self) -> None:
        """Load sessions from storage."""
        try:
            with open(self._storage_path, "r") as f:
                data = json.load(f)
            
            self._active_session = data.get("active_session")
            
            for session_id, session_data in data.get("sessions", {}).items():
                self._sessions[session_id] = Session.from_dict(session_data)
            
            logger.debug(f"Loaded {len(self._sessions)} sessions")
            
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to load sessions: {e}")