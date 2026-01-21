"""Base reporter class."""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseReporter(ABC):
    """Abstract base class for report generators."""
    
    @abstractmethod
    def generate(self, data: Dict[str, Any]) -> str:
        """
        Generate report from scan data.
        
        Args:
            data: Scan results data
            
        Returns:
            Formatted report string
        """
        pass