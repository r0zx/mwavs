"""
Centralized logging configuration for the scanner.
Provides structured logging with multiple output handlers.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json
from logging.handlers import RotatingFileHandler
import threading


class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs structured JSON logs."""

    def __init__(self, include_extras: bool = True):
        super().__init__()
        self.include_extras = include_extras

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.thread,
            "thread_name": record.threadName,
        }

        # Include extra fields if present
        if self.include_extras and hasattr(record, "extra_data"):
            log_data["extra"] = record.extra_data

        # Include exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, default=str)


class ColoredFormatter(logging.Formatter):
    """Colored console formatter for better readability."""

    COLORS = {
        "DEBUG": "\033[36m",      # Cyan
        "INFO": "\033[32m",       # Green
        "WARNING": "\033[33m",    # Yellow
        "ERROR": "\033[31m",      # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def __init__(self, use_colors: bool = True):
        super().__init__(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors and record.levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelname]}{self.BOLD}"
                f"{record.levelname}{self.RESET}"
            )
        return super().format(record)


class ScannerLoggerAdapter(logging.LoggerAdapter):
    """Custom logger adapter for adding context to log messages."""

    def __init__(self, logger: logging.Logger, extra: Optional[Dict] = None):
        super().__init__(logger, extra or {})
        self._context = threading.local()

    def process(self, msg: str, kwargs: Dict) -> tuple:
        extra = kwargs.get("extra", {})
        extra.update(self.extra)
        
        # Add thread-local context
        if hasattr(self._context, "data"):
            extra.update(self._context.data)
        
        kwargs["extra"] = extra
        return msg, kwargs

    def set_context(self, **kwargs):
        """Set thread-local context for logging."""
        if not hasattr(self._context, "data"):
            self._context.data = {}
        self._context.data.update(kwargs)

    def clear_context(self):
        """Clear thread-local context."""
        if hasattr(self._context, "data"):
            self._context.data.clear()


# Global logger registry
_loggers: Dict[str, ScannerLoggerAdapter] = {}
_initialized = False
_lock = threading.Lock()


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = False,
    use_colors: bool = True,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
) -> None:
    """
    Configure the logging system for the scanner.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        json_format: If True, use JSON formatting for console output
        use_colors: If True, use colored console output
        max_file_size: Maximum log file size before rotation
        backup_count: Number of backup files to keep
    """
    global _initialized

    with _lock:
        if _initialized:
            return

        # Get root scanner logger
        root_logger = logging.getLogger("mwavs")
        root_logger.setLevel(getattr(logging, level.upper()))

        # Remove existing handlers
        root_logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        
        if json_format:
            console_handler.setFormatter(StructuredFormatter())
        else:
            console_handler.setFormatter(ColoredFormatter(use_colors=use_colors))
        
        root_logger.addHandler(console_handler)

        # File handler (if specified)
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = RotatingFileHandler(
                log_path,
                maxBytes=max_file_size,
                backupCount=backup_count,
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(StructuredFormatter())
            root_logger.addHandler(file_handler)

        _initialized = True


def get_logger(name: str) -> ScannerLoggerAdapter:
    """
    Get or create a logger with the given name.
    
    Args:
        name: Logger name (will be prefixed with 'mwavs.')
    
    Returns:
        Configured logger adapter
    """
    full_name = f"mwavs.{name}" if not name.startswith("mwavs.") else name
    
    with _lock:
        if full_name not in _loggers:
            logger = logging.getLogger(full_name)
            _loggers[full_name] = ScannerLoggerAdapter(logger)
        
        return _loggers[full_name]


class LogContext:
    """Context manager for adding temporary logging context."""

    def __init__(self, logger: ScannerLoggerAdapter, **context):
        self.logger = logger
        self.context = context
        self._previous_context = {}

    def __enter__(self):
        if hasattr(self.logger._context, "data"):
            self._previous_context = self.logger._context.data.copy()
        self.logger.set_context(**self.context)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.clear_context()
        if self._previous_context:
            self.logger.set_context(**self._previous_context)
        return False