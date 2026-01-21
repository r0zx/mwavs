"""
Core HTTP engine for the scanner.
Handles all HTTP communications with robust error handling,
retry logic, and session management.
"""

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, List, Any, Callable, Union, Tuple
from dataclasses import dataclass, field
from queue import Queue, Empty
import ssl
import socket
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

from .config import ScannerConfig, ProxyConfig
from .request_wrapper import RequestWrapper, HTTPMethod
from .response_wrapper import ResponseWrapper
from .session_manager import SessionManager, Session
from .exceptions import (
    RequestException,
    ConnectionException,
    TimeoutException,
    ProxyException,
    RateLimitException,
    WAFBlockException,
)
from .utils import URLUtils, ResponseAnalyzer, RateLimiter, RandomUtils
from .logger import get_logger, LogContext

# Suppress insecure request warnings when SSL verification is disabled
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = get_logger("engine")


@dataclass
class RequestStats:
    """Statistics for HTTP requests."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    total_time: float = 0.0
    retries: int = 0
    timeouts: int = 0
    
    def record_request(
        self,
        success: bool,
        bytes_sent: int,
        bytes_received: int,
        elapsed: float,
        retried: bool = False
    ):
        """Record statistics for a request."""
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
        self.total_bytes_sent += bytes_sent
        self.total_bytes_received += bytes_received
        self.total_time += elapsed
        if retried:
            self.retries += 1
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests
    
    @property
    def avg_response_time(self) -> float:
        """Calculate average response time."""
        if self.total_requests == 0:
            return 0.0
        return self.total_time / self.total_requests
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'success_rate': f"{self.success_rate:.2%}",
            'total_bytes_sent': self.total_bytes_sent,
            'total_bytes_received': self.total_bytes_received,
            'avg_response_time': f"{self.avg_response_time:.3f}s",
            'retries': self.retries,
            'timeouts': self.timeouts,
        }


class HTTPEngine:
    """
    Production-grade HTTP engine with comprehensive features.
    
    Features:
    - GET, POST, PUT, DELETE support
    - Automatic redirect handling
    - Timeout management
    - Retry logic with exponential backoff
    - Cookie and session handling
    - Proxy support
    - Concurrent request execution
    - Rate limiting
    - WAF detection
    """
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self._session: Optional[requests.Session] = None
        self._session_manager = SessionManager()
        self._stats = RequestStats()
        self._rate_limiter: Optional[RateLimiter] = None
        self._lock = threading.RLock()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._baseline_responses: Dict[str, ResponseWrapper] = {}
        
        # Initialize rate limiter if configured
        if config.concurrency.rate_limit:
            self._rate_limiter = RateLimiter(config.concurrency.rate_limit)
        
        # Request hooks
        self._pre_request_hooks: List[Callable] = []
        self._post_request_hooks: List[Callable] = []
        
        self._initialize_session()
    
    def _initialize_session(self):
        """Initialize the requests session with proper configuration."""
        self._session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.request.max_retries,
            backoff_factor=self.config.request.retry_delay,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            raise_on_status=False,
        )
        
        # Mount adapters for both HTTP and HTTPS
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.config.concurrency.max_concurrent_requests,
            pool_maxsize=self.config.concurrency.max_concurrent_requests,
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        
        # Set default headers
        self._session.headers.update({
            'User-Agent': self.config.request.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        self._session.headers.update(self.config.request.default_headers)
        
        # Set cookies
        for name, value in self.config.request.cookies.items():
            self._session.cookies.set(name, value)
        
        # Configure proxies
        if self.config.proxy:
            self._session.proxies = self.config.proxy.to_dict()
            if not self.config.proxy.verify_ssl:
                self._session.verify = False
        
        # Configure SSL verification
        self._session.verify = self.config.request.verify_ssl
        
        logger.info("HTTP engine initialized")
    
    def add_pre_request_hook(self, hook: Callable[[RequestWrapper], RequestWrapper]):
        """Add a hook to be called before each request."""
        self._pre_request_hooks.append(hook)
    
    def add_post_request_hook(self, hook: Callable[[ResponseWrapper], None]):
        """Add a hook to be called after each response."""
        self._post_request_hooks.append(hook)
    
    def request(
        self,
        request: RequestWrapper,
        follow_redirects: Optional[bool] = None,
        timeout: Optional[float] = None,
    ) -> ResponseWrapper:
        """
        Execute a single HTTP request.
        
        Args:
            request: The request wrapper to execute
            follow_redirects: Override config's redirect setting
            timeout: Override config's timeout setting
            
        Returns:
            ResponseWrapper containing the response
            
        Raises:
            RequestException: On request failure
            TimeoutException: On timeout
            ConnectionException: On connection failure
        """
        # Apply rate limiting
        if self._rate_limiter:
            self._rate_limiter.wait()
        
        # Apply pre-request hooks
        for hook in self._pre_request_hooks:
            request = hook(request)
        
        # Determine settings
        allow_redirects = (
            follow_redirects if follow_redirects is not None
            else request.allow_redirects
        )
        req_timeout = timeout or request.timeout or self.config.request.timeout
        
        # Build request kwargs
        kwargs = {
            'method': request.method.value,
            'url': request.build_full_url(),
            'headers': dict(request.headers),
            'timeout': req_timeout,
            'allow_redirects': allow_redirects,
            'verify': request.verify_ssl and self.config.request.verify_ssl,
        }
        
        # Add body data
        if request.data:
            if isinstance(request.data, dict):
                kwargs['data'] = request.data
            else:
                kwargs['data'] = str(request.data)
        
        if request.json_data:
            kwargs['json'] = request.json_data
        
        # Add cookies
        if request.cookies:
            kwargs['cookies'] = request.cookies
        
        # Add proxy if configured
        if self.config.proxy:
            kwargs['proxies'] = self.config.proxy.to_dict()
        
        start_time = time.time()
        retried = False
        
        with LogContext(logger, url=request.url, method=request.method.value):
            try:
                logger.debug(f"Sending {request.method.value} request to {request.url}")
                
                response = self._session.request(**kwargs)
                elapsed = time.time() - start_time
                
                # Build response wrapper
                redirect_history = [r.url for r in response.history]
                
                # Extract cookies from response
                response_cookies = {}
                for cookie in response.cookies:
                    response_cookies[cookie.name] = cookie.value
                
                wrapped_response = ResponseWrapper(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.content,
                    url=response.url,
                    elapsed_time=elapsed,
                    request_fingerprint=request.fingerprint,
                    redirect_history=redirect_history,
                    cookies=response_cookies,
                )
                
                # Check for WAF blocking
                waf = ResponseAnalyzer.detect_waf(
                    wrapped_response.headers,
                    wrapped_response.text[:5000]
                )
                if waf and wrapped_response.status_code in (403, 406, 429, 503):
                    logger.warning(f"Possible WAF block detected: {waf}")
                    raise WAFBlockException(
                        f"Request blocked by WAF: {waf}",
                        url=request.url,
                        waf_signature=waf,
                    )
                
                # Check for rate limiting
                if wrapped_response.status_code == 429:
                    retry_after = wrapped_response.get_header('Retry-After')
                    raise RateLimitException(
                        "Rate limited",
                        url=request.url,
                        retry_after=int(retry_after) if retry_after else None,
                    )
                
                # Record statistics
                self._stats.record_request(
                    success=True,
                    bytes_sent=len(str(kwargs.get('data', ''))),
                    bytes_received=len(response.content),
                    elapsed=elapsed,
                    retried=retried,
                )
                
                logger.debug(
                    f"Response: {response.status_code} "
                    f"({len(response.content)} bytes, {elapsed:.3f}s)"
                )
                
                # Apply post-request hooks
                for hook in self._post_request_hooks:
                    hook(wrapped_response)
                
                return wrapped_response
                
            except requests.exceptions.Timeout as e:
                self._stats.timeouts += 1
                raise TimeoutException(
                    f"Request timed out after {req_timeout}s",
                    url=request.url,
                    method=request.method.value,
                    cause=e,
                )
            
            except requests.exceptions.ProxyError as e:
                raise ProxyException(
                    "Proxy connection failed",
                    url=request.url,
                    cause=e,
                )
            
            except requests.exceptions.ConnectionError as e:
                raise ConnectionException(
                    "Connection failed",
                    url=request.url,
                    cause=e,
                )
            
            except requests.exceptions.RequestException as e:
                self._stats.record_request(
                    success=False,
                    bytes_sent=0,
                    bytes_received=0,
                    elapsed=time.time() - start_time,
                )
                raise RequestException(
                    f"Request failed: {str(e)}",
                    url=request.url,
                    method=request.method.value,
                    cause=e,
                )
    
    def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> ResponseWrapper:
        """Convenience method for GET requests."""
        request = RequestWrapper(
            url=url,
            method=HTTPMethod.GET,
            params=params or {},
            headers=headers or {},
            **kwargs
        )
        return self.request(request)
    
    def post(
        self,
        url: str,
        data: Optional[Union[Dict, str]] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> ResponseWrapper:
        """Convenience method for POST requests."""
        request = RequestWrapper(
            url=url,
            method=HTTPMethod.POST,
            data=data,
            json_data=json_data,
            headers=headers or {},
            **kwargs
        )
        return self.request(request)
    
    def put(
        self,
        url: str,
        data: Optional[Union[Dict, str]] = None,
        json_data: Optional[Dict] = None,
        **kwargs
    ) -> ResponseWrapper:
        """Convenience method for PUT requests."""
        request = RequestWrapper(
            url=url,
            method=HTTPMethod.PUT,
            data=data,
            json_data=json_data,
            **kwargs
        )
        return self.request(request)
    
    def delete(self, url: str, **kwargs) -> ResponseWrapper:
        """Convenience method for DELETE requests."""
        request = RequestWrapper(
            url=url,
            method=HTTPMethod.DELETE,
            **kwargs
        )
        return self.request(request)
    
    def request_batch(
        self,
        requests_list: List[RequestWrapper],
        callback: Optional[Callable[[RequestWrapper, ResponseWrapper], None]] = None,
        error_callback: Optional[Callable[[RequestWrapper, Exception], None]] = None,
    ) -> List[Tuple[RequestWrapper, Union[ResponseWrapper, Exception]]]:
        """
        Execute multiple requests concurrently.
        
        Args:
            requests_list: List of requests to execute
            callback: Optional callback for successful responses
            error_callback: Optional callback for failed requests
            
        Returns:
            List of (request, response/exception) tuples
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=self.config.concurrency.threads) as executor:
            futures = {
                executor.submit(self.request, req): req
                for req in requests_list
            }
            
            for future in as_completed(futures):
                req = futures[future]
                try:
                    response = future.result()
                    results.append((req, response))
                    
                    if callback:
                        callback(req, response)
                        
                except Exception as e:
                    results.append((req, e))
                    
                    if error_callback:
                        error_callback(req, e)
                    else:
                        logger.warning(f"Request failed: {req.url} - {e}")
        
        return results
    
    def get_baseline(
        self,
        url: str,
        method: HTTPMethod = HTTPMethod.GET,
        force_refresh: bool = False
    ) -> ResponseWrapper:
        """
        Get baseline response for comparison.
        Cached to avoid redundant requests.
        """
        cache_key = f"{method.value}:{url}"
        
        if not force_refresh and cache_key in self._baseline_responses:
            return self._baseline_responses[cache_key]
        
        request = RequestWrapper(url=url, method=method)
        response = self.request(request)
        
        self._baseline_responses[cache_key] = response
        return response
    
    def test_connection(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Test connection to target URL.
        
        Returns:
            Tuple of (success, error_message)
        """
        try:
            response = self.get(url, timeout=10)
            return (True, None)
        except TimeoutException:
            return (False, "Connection timed out")
        except ConnectionException as e:
            return (False, f"Connection failed: {e.message}")
        except Exception as e:
            return (False, str(e))
    
    def detect_waf(self, url: str) -> Optional[str]:
        """
        Attempt to detect WAF presence on target.
        
        Returns:
            WAF name if detected, None otherwise
        """
        # Send a potentially malicious-looking request
        test_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "{{7*7}}",
        ]
        
        for payload in test_payloads:
            try:
                request = RequestWrapper(
                    url=url,
                    params={'test': payload}
                )
                response = self.request(request)
                
                waf = ResponseAnalyzer.detect_waf(
                    response.headers,
                    response.text[:5000]
                )
                if waf:
                    return waf
                    
            except WAFBlockException as e:
                return e.waf_signature
            except Exception:
                pass
        
        return None
    
    @property
    def stats(self) -> RequestStats:
        """Get request statistics."""
        return self._stats
    
    def reset_stats(self):
        """Reset request statistics."""
        self._stats = RequestStats()
    
    def close(self):
        """Close the HTTP engine and clean up resources."""
        if self._session:
            self._session.close()
            self._session = None
        
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None
        
        logger.info(f"HTTP engine closed. Stats: {self._stats.to_dict()}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False