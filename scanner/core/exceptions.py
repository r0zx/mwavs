"""
Custom exception hierarchy for the scanner.
Provides granular error handling and meaningful error messages.
"""

from typing import Optional, Dict, Any
import traceback


class ScannerException(Exception):
    """Base exception for all scanner-related errors."""

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.cause = cause
        self.traceback = traceback.format_exc() if cause else None

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/reporting."""
        return {
            "type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
            "cause": str(self.cause) if self.cause else None,
        }

    def __str__(self) -> str:
        base = f"{self.__class__.__name__}: {self.message}"
        if self.details:
            base += f" | Details: {self.details}"
        if self.cause:
            base += f" | Caused by: {self.cause}"
        return base


class RequestException(ScannerException):
    """Exception raised during HTTP request operations."""

    def __init__(
        self,
        message: str,
        url: Optional[str] = None,
        method: Optional[str] = None,
        status_code: Optional[int] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        details.update(
            {"url": url, "method": method, "status_code": status_code}
        )
        super().__init__(message, details=details, **kwargs)
        self.url = url
        self.method = method
        self.status_code = status_code


class ConnectionException(RequestException):
    """Exception for connection-related failures."""

    pass


class TimeoutException(RequestException):
    """Exception for request timeout scenarios."""

    pass


class ProxyException(RequestException):
    """Exception for proxy-related issues."""

    pass


class PluginException(ScannerException):
    """Exception raised by scanner plugins."""

    def __init__(
        self,
        message: str,
        plugin_name: Optional[str] = None,
        target: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        details.update({"plugin_name": plugin_name, "target": target})
        super().__init__(message, details=details, **kwargs)
        self.plugin_name = plugin_name
        self.target = target


class PluginLoadException(PluginException):
    """Exception when plugin fails to load."""

    pass


class PluginExecutionException(PluginException):
    """Exception during plugin execution."""

    pass


class ConfigurationException(ScannerException):
    """Exception for configuration-related errors."""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_value: Optional[Any] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        details.update({"config_key": config_key, "config_value": config_value})
        super().__init__(message, details=details, **kwargs)


class ValidationException(ScannerException):
    """Exception for input validation failures."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        details.update({"field": field, "value": value})
        super().__init__(message, details=details, **kwargs)


class RateLimitException(RequestException):
    """Exception when rate limiting is detected."""

    def __init__(
        self,
        message: str,
        retry_after: Optional[int] = None,
        **kwargs,
    ):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class WAFBlockException(RequestException):
    """Exception when WAF blocks the request."""

    def __init__(
        self,
        message: str,
        waf_signature: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        details.update({"waf_signature": waf_signature})
        super().__init__(message, details=details, **kwargs)
        self.waf_signature = waf_signature


class ReportingException(ScannerException):
    """Exception during report generation."""

    pass