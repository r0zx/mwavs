"""
MWAVS - Modular Web Application Vulnerability Scanner
A production-grade, plugin-driven web security scanner.
"""

__version__ = "1.0.0"
__author__ = "Security Engineering Team"
__license__ = "MIT"

from mwavs.core.engine import HTTPEngine
from mwavs.core.config import ScannerConfig
from mwavs.core.logger import get_logger

__all__ = ["HTTPEngine", "ScannerConfig", "get_logger", "__version__"]