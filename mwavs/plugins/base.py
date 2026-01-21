"""
Base plugin class and interfaces for the scanner.
All plugins must inherit from BasePlugin.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Generator
from enum import Enum
from datetime import datetime

from mwavs.core.engine import HTTPEngine
from mwavs.core.config import ScannerConfig, Severity
from mwavs.core.request_wrapper import RequestWrapper
from mwavs.core.response_wrapper import ResponseWrapper
from mwavs.core.utils import Finding, PayloadManager, WordlistManager
from mwavs.core.logger import get_logger


class PluginCategory(Enum):
    """Categories for organizing plugins."""
    INJECTION = "injection"
    XSS = "xss"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    INFORMATION = "information"
    ENUMERATION = "enumeration"


@dataclass
class PluginContext:
    """
    Context passed to plugins during execution.
    Contains all information needed for scanning.
    """
    target_url: str
    config: ScannerConfig
    engine: HTTPEngine
    
    # Optional context data
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body_params: Dict[str, str] = field(default_factory=dict)
    
    # Baseline response for comparison
    baseline_response: Optional[ResponseWrapper] = None
    
    # Custom data from other plugins
    shared_data: Dict[str, Any] = field(default_factory=dict)
    
    # Discovered endpoints
    endpoints: List[str] = field(default_factory=list)
    
    # Forms discovered in the target
    forms: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PluginResult:
    """
    Result from plugin execution.
    """
    plugin_name: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    requests_made: int = 0
    
    # Status
    completed: bool = True
    aborted: bool = False
    abort_reason: Optional[str] = None
    
    # Metadata
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def add_finding(self, finding: Finding):
        """Add a finding to results."""
        self.findings.append(finding)
    
    def add_error(self, error: str):
        """Add an error message."""
        self.errors.append(error)
    
    @property
    def has_findings(self) -> bool:
        """Check if any findings were discovered."""
        return len(self.findings) > 0
    
    @property
    def critical_findings(self) -> List[Finding]:
        """Get critical severity findings."""
        return [f for f in self.findings if f.severity == 'critical']
    
    @property
    def high_findings(self) -> List[Finding]:
        """Get high severity findings."""
        return [f for f in self.findings if f.severity == 'high']
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'plugin_name': self.plugin_name,
            'findings': [f.to_dict() for f in self.findings],
            'findings_count': len(self.findings),
            'errors': self.errors,
            'execution_time': self.execution_time,
            'requests_made': self.requests_made,
            'completed': self.completed,
            'aborted': self.aborted,
            'abort_reason': self.abort_reason,
        }


class BasePlugin(ABC):
    """
    Abstract base class for all scanner plugins.
    
    Plugins must implement the `run` method and define
    class attributes for metadata.
    """
    
    # Required class attributes (must be overridden)
    name: str = "base"
    description: str = "Base plugin class"
    
    # Optional class attributes
    category: PluginCategory = PluginCategory.INFORMATION
    author: str = "Unknown"
    version: str = "1.0.0"
    default_severity: str = "medium"
    
    # Plugin dependencies
    dependencies: List[str] = []
    
    # CVSS and references
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    references: List[str] = []
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        """
        Initialize the plugin.
        
        Args:
            config: Scanner configuration
        """
        self.config = config or ScannerConfig()
        self.logger = get_logger(f"plugin.{self.name}")
        self._payload_manager: Optional[PayloadManager] = None
        self._wordlist_manager: Optional[WordlistManager] = None
        self._stop_requested = False
    
    @property
    def payload_manager(self) -> PayloadManager:
        """Get the payload manager."""
        if self._payload_manager is None:
            self._payload_manager = PayloadManager(self.config.payloads_dir)
        return self._payload_manager
    
    @property
    def wordlist_manager(self) -> WordlistManager:
        """Get the wordlist manager."""
        if self._wordlist_manager is None:
            self._wordlist_manager = WordlistManager(self.config.wordlists_dir)
        return self._wordlist_manager
    
    @abstractmethod
    def run(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> PluginResult:
        """
        Execute the plugin scan.
        
        Args:
            engine: HTTP engine for making requests
            target: Target URL to scan
            context: Plugin context with additional data
            
        Returns:
            PluginResult containing findings and metadata
        """
        pass
    
    def stop(self):
        """Request the plugin to stop execution."""
        self._stop_requested = True
        self.logger.info("Stop requested")
    
    def should_stop(self) -> bool:
        """Check if stop has been requested."""
        return self._stop_requested
    
    def reset(self):
        """Reset plugin state for reuse."""
        self._stop_requested = False
    
    def create_finding(
        self,
        vulnerability_type: str,
        url: str,
        severity: Optional[str] = None,
        confidence: float = 80.0,
        **kwargs
    ) -> Finding:
        """
        Helper method to create a finding.
        
        Args:
            vulnerability_type: Type of vulnerability
            url: Affected URL
            severity: Severity level (uses default if not specified)
            confidence: Confidence score (0-100)
            **kwargs: Additional finding attributes
            
        Returns:
            Finding instance
        """
        return Finding(
            plugin_name=self.name,
            vulnerability_type=vulnerability_type,
            severity=severity or self.default_severity,
            confidence=confidence,
            url=url,
            references=self.references.copy(),
            **kwargs
        )
    
    def create_result(self) -> PluginResult:
        """Create an empty plugin result."""
        result = PluginResult(plugin_name=self.name)
        result.started_at = datetime.utcnow()
        return result
    
    def validate_target(self, target: str) -> bool:
        """
        Validate that the target is suitable for this plugin.
        Override in subclasses for custom validation.
        
        Args:
            target: Target URL
            
        Returns:
            True if target is valid
        """
        return True
    
    def get_payloads(self) -> List[str]:
        """
        Get payloads for this plugin.
        Override in subclasses to provide custom payloads.
        
        Returns:
            List of payload strings
        """
        return self.payload_manager.load(self.name)
    
    def preprocess(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> PluginContext:
        """
        Preprocess hook called before run().
        Override to perform setup tasks.
        
        Args:
            engine: HTTP engine
            target: Target URL
            context: Plugin context
            
        Returns:
            Modified context
        """
        return context
    
    def postprocess(self, result: PluginResult) -> PluginResult:
        """
        Postprocess hook called after run().
        Override to perform cleanup or result modification.
        
        Args:
            result: Plugin result
            
        Returns:
            Modified result
        """
        result.completed_at = datetime.utcnow()
        if result.started_at:
            result.execution_time = (
                result.completed_at - result.started_at
            ).total_seconds()
        return result
    
    def __str__(self) -> str:
        return f"Plugin({self.name})"
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name}, version={self.version})>"


class PassivePlugin(BasePlugin):
    """
    Base class for passive analysis plugins.
    These plugins analyze existing responses without making additional requests.
    """
    
    def run(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> PluginResult:
        """Execute passive analysis."""
        result = self.create_result()
        
        if context.baseline_response:
            findings = self.analyze(context.baseline_response, context)
            for finding in findings:
                result.add_finding(finding)
        
        return self.postprocess(result)
    
    @abstractmethod
    def analyze(
        self,
        response: ResponseWrapper,
        context: PluginContext
    ) -> List[Finding]:
        """
        Analyze a response for issues.
        
        Args:
            response: Response to analyze
            context: Plugin context
            
        Returns:
            List of findings
        """
        pass


class ActivePlugin(BasePlugin):
    """
    Base class for active scanning plugins.
    These plugins actively probe the target with payloads.
    """
    
    # Maximum number of requests per parameter
    max_requests_per_param: int = 100
    
    def run(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> PluginResult:
        """Execute active scanning."""
        result = self.create_result()
        
        try:
            # Get injectable parameters
            parameters = self.get_injection_points(target, context)
            
            for param_name, param_value, param_location in parameters:
                if self.should_stop():
                    result.aborted = True
                    result.abort_reason = "Stop requested"
                    break
                
                # Test this parameter
                findings = self.test_parameter(
                    engine, target, param_name, param_value,
                    param_location, context
                )
                
                for finding in findings:
                    result.add_finding(finding)
                    result.requests_made += 1
                    
                    # Stop on first finding if configured
                    if (
                        self.config.plugins.stop_on_first_finding
                        and result.has_findings
                    ):
                        return self.postprocess(result)
        
        except Exception as e:
            result.add_error(str(e))
            self.logger.error(f"Error during scan: {e}")
        
        return self.postprocess(result)
    
    def get_injection_points(
        self,
        target: str,
        context: PluginContext
    ) -> List[tuple]:
        """
        Get all injection points to test.
        
        Returns:
            List of (param_name, param_value, location) tuples
        """
        points = []
        
        # URL parameters
        for name, value in context.parameters.items():
            points.append((name, value, 'url'))
        
        # Body parameters
        for name, value in context.body_params.items():
            points.append((name, value, 'body'))
        
        # Headers (selected)
        injectable_headers = ['User-Agent', 'Referer', 'X-Forwarded-For']
        for header in injectable_headers:
            if header in context.headers:
                points.append((header, context.headers[header], 'header'))
        
        return points
    
    @abstractmethod
    def test_parameter(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext
    ) -> List[Finding]:
        """
        Test a specific parameter for vulnerabilities.
        
        Args:
            engine: HTTP engine
            target: Target URL
            param_name: Parameter name
            param_value: Original parameter value
            location: Parameter location (url, body, header)
            context: Plugin context
            
        Returns:
            List of findings for this parameter
        """
        pass