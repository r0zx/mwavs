"""
Scanner configuration management.
Supports file-based and programmatic configuration.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, List, Any, Set
import json
import yaml
from enum import Enum

from .exceptions import ConfigurationException
from .logger import get_logger

logger = get_logger("config")


class ScanMode(Enum):
    """Available scan modes."""
    ALL = "all"
    MANUAL = "manual"
    XSS = "xss"
    SQLI = "sqli"
    DIR = "dir"
    CORS = "cors"
    SSRF = "ssrf"
    OPENREDIRECT = "openredirect"


class OutputFormat(Enum):
    """Available output formats."""
    JSON = "json"
    HTML = "html"
    TXT = "txt"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def numeric_value(self) -> int:
        """Get numeric value for sorting."""
        values = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        return values.get(self.value, 0)


@dataclass
class ProxyConfig:
    """Proxy configuration settings."""
    http: Optional[str] = None
    https: Optional[str] = None
    verify_ssl: bool = True
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to requests-compatible proxy dict."""
        proxies = {}
        if self.http:
            proxies["http"] = self.http
        if self.https:
            proxies["https"] = self.https
        elif self.http:
            # Use HTTP proxy for HTTPS if not specified
            proxies["https"] = self.http
        return proxies

    @classmethod
    def from_string(cls, proxy_str: str) -> "ProxyConfig":
        """Create ProxyConfig from a single proxy string."""
        return cls(http=proxy_str, https=proxy_str)


@dataclass
class RequestConfig:
    """HTTP request configuration settings."""
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    follow_redirects: bool = True
    max_redirects: int = 10
    verify_ssl: bool = True
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    default_headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class ConcurrencyConfig:
    """Concurrency and threading configuration."""
    threads: int = 10
    max_concurrent_requests: int = 50
    request_delay: float = 0.0
    rate_limit: Optional[int] = None  # Requests per second


@dataclass
class PluginConfig:
    """Plugin-specific configuration settings."""
    enabled_plugins: Set[str] = field(default_factory=lambda: {
        "xss", "sqli", "dir_enum", "open_redirect", "ssrf", "cors"
    })
    plugin_timeout: float = 300.0
    max_payloads_per_param: int = 50
    stop_on_first_finding: bool = False
    custom_payloads_path: Optional[Path] = None
    custom_wordlists_path: Optional[Path] = None


@dataclass
class ReportConfig:
    """Report generation configuration."""
    output_format: OutputFormat = OutputFormat.JSON
    output_path: Optional[Path] = None
    include_evidence: bool = True
    include_raw_requests: bool = True
    include_raw_responses: bool = True
    max_evidence_length: int = 5000
    template_path: Optional[Path] = None


@dataclass
class ScannerConfig:
    """
    Main scanner configuration container.
    Aggregates all configuration settings.
    """
    # Target configuration
    target_url: Optional[str] = None
    target_scope: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    
    # Scan mode
    scan_mode: ScanMode = ScanMode.ALL
    
    # Sub-configurations
    request: RequestConfig = field(default_factory=RequestConfig)
    proxy: Optional[ProxyConfig] = None
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    plugins: PluginConfig = field(default_factory=PluginConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    
    # Logging
    verbose: bool = False
    debug: bool = False
    log_file: Optional[Path] = None
    
    # Data paths
    data_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "data")
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate()
    
    def _validate(self):
        """Validate configuration values."""
        if self.concurrency.threads < 1:
            raise ConfigurationException(
                "Thread count must be at least 1",
                config_key="concurrency.threads",
                config_value=self.concurrency.threads,
            )
        
        if self.request.timeout < 0:
            raise ConfigurationException(
                "Timeout must be non-negative",
                config_key="request.timeout",
                config_value=self.request.timeout,
            )
        
        if self.request.max_retries < 0:
            raise ConfigurationException(
                "Max retries must be non-negative",
                config_key="request.max_retries",
                config_value=self.request.max_retries,
            )

    @property
    def payloads_dir(self) -> Path:
        """Get the payloads directory path."""
        if self.plugins.custom_payloads_path:
            return self.plugins.custom_payloads_path
        return self.data_dir / "payloads"
    
    @property
    def wordlists_dir(self) -> Path:
        """Get the wordlists directory path."""
        if self.plugins.custom_wordlists_path:
            return self.plugins.custom_wordlists_path
        return self.data_dir / "wordlists"
    
    def get_log_level(self) -> str:
        """Determine logging level from config."""
        if self.debug:
            return "DEBUG"
        elif self.verbose:
            return "INFO"
        return "WARNING"

    @classmethod
    def from_file(cls, config_path: Path) -> "ScannerConfig":
        """
        Load configuration from a file (JSON or YAML).
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Populated ScannerConfig instance
        """
        if not config_path.exists():
            raise ConfigurationException(
                f"Configuration file not found: {config_path}",
                config_key="config_path",
                config_value=str(config_path),
            )
        
        with open(config_path, "r") as f:
            if config_path.suffix in (".yaml", ".yml"):
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
        
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScannerConfig":
        """
        Create configuration from a dictionary.
        
        Args:
            data: Configuration dictionary
            
        Returns:
            Populated ScannerConfig instance
        """
        # Process nested configurations
        request_data = data.pop("request", {})
        proxy_data = data.pop("proxy", None)
        concurrency_data = data.pop("concurrency", {})
        plugins_data = data.pop("plugins", {})
        report_data = data.pop("report", {})
        
        # Handle enums
        if "scan_mode" in data:
            data["scan_mode"] = ScanMode(data["scan_mode"])
        
        if "output_format" in report_data:
            report_data["output_format"] = OutputFormat(report_data["output_format"])
        
        # Handle paths
        for key in ("output_path", "template_path"):
            if key in report_data and report_data[key]:
                report_data[key] = Path(report_data[key])
        
        if "log_file" in data and data["log_file"]:
            data["log_file"] = Path(data["log_file"])
        
        if "data_dir" in data and data["data_dir"]:
            data["data_dir"] = Path(data["data_dir"])
        
        # Build configuration objects
        config = cls(
            **data,
            request=RequestConfig(**request_data),
            proxy=ProxyConfig(**proxy_data) if proxy_data else None,
            concurrency=ConcurrencyConfig(**concurrency_data),
            plugins=PluginConfig(**plugins_data),
            report=ReportConfig(**report_data),
        )
        
        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "target_url": self.target_url,
            "target_scope": self.target_scope,
            "exclude_patterns": self.exclude_patterns,
            "scan_mode": self.scan_mode.value,
            "request": {
                "timeout": self.request.timeout,
                "max_retries": self.request.max_retries,
                "retry_delay": self.request.retry_delay,
                "follow_redirects": self.request.follow_redirects,
                "max_redirects": self.request.max_redirects,
                "verify_ssl": self.request.verify_ssl,
                "user_agent": self.request.user_agent,
                "default_headers": self.request.default_headers,
                "cookies": self.request.cookies,
            },
            "proxy": self.proxy.to_dict() if self.proxy else None,
            "concurrency": {
                "threads": self.concurrency.threads,
                "max_concurrent_requests": self.concurrency.max_concurrent_requests,
                "request_delay": self.concurrency.request_delay,
                "rate_limit": self.concurrency.rate_limit,
            },
            "plugins": {
                "enabled_plugins": list(self.plugins.enabled_plugins),
                "plugin_timeout": self.plugins.plugin_timeout,
                "max_payloads_per_param": self.plugins.max_payloads_per_param,
                "stop_on_first_finding": self.plugins.stop_on_first_finding,
            },
            "report": {
                "output_format": self.report.output_format.value,
                "output_path": str(self.report.output_path) if self.report.output_path else None,
                "include_evidence": self.report.include_evidence,
                "include_raw_requests": self.report.include_raw_requests,
                "include_raw_responses": self.report.include_raw_responses,
            },
            "verbose": self.verbose,
            "debug": self.debug,
        }

    def merge_cli_args(self, args: Any) -> "ScannerConfig":
        """
        Merge CLI arguments into the configuration.
        CLI arguments take precedence over file configuration.
        
        Args:
            args: Parsed CLI arguments (argparse.Namespace)
            
        Returns:
            Updated configuration instance
        """
        if hasattr(args, "url") and args.url:
            self.target_url = args.url
        
        if hasattr(args, "scan") and args.scan:
            try:
                self.scan_mode = ScanMode(args.scan)
            except ValueError:
                # Handle specific plugin names
                pass
        
        if hasattr(args, "threads") and args.threads:
            self.concurrency.threads = args.threads
        
        if hasattr(args, "timeout") and args.timeout:
            self.request.timeout = args.timeout
        
        if hasattr(args, "proxy") and args.proxy:
            self.proxy = ProxyConfig.from_string(args.proxy)
        
        if hasattr(args, "output") and args.output:
            self.report.output_format = OutputFormat(args.output)
        
        if hasattr(args, "verbose") and args.verbose:
            self.verbose = args.verbose
        
        if hasattr(args, "debug") and args.debug:
            self.debug = args.debug
        
        return self


# Default configuration instance
DEFAULT_CONFIG = ScannerConfig()