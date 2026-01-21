"""
Plugin system for the vulnerability scanner.
Provides plugin discovery, loading, and management.
"""

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Dict, List, Type, Optional, Any
import threading

from .base import BasePlugin, PluginResult, PluginContext
from scanner.core.logger import get_logger
from scanner.core.exceptions import PluginLoadException, PluginException

logger = get_logger("plugins")


class PluginRegistry:
    """
    Registry for managing scanner plugins.
    Handles discovery, loading, and lifecycle management.
    """
    
    _instance: Optional["PluginRegistry"] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Singleton pattern for plugin registry."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._plugins: Dict[str, Type[BasePlugin]] = {}
        self._instances: Dict[str, BasePlugin] = {}
        self._plugin_dir = Path(__file__).parent
        self._initialized = True
    
    def discover_plugins(self) -> List[str]:
        """
        Discover all available plugins in the plugins directory.
        
        Returns:
            List of discovered plugin names
        """
        discovered = []
        
        # Get the package path
        package_path = str(self._plugin_dir)
        
        # Iterate through all modules in the package
        for _, module_name, is_pkg in pkgutil.iter_modules([package_path]):
            if module_name.startswith('_') or module_name == 'base':
                continue
            
            try:
                # Import the module
                module = importlib.import_module(f".{module_name}", package="scanner.plugins")
                
                # Find plugin classes in the module
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, BasePlugin)
                        and obj is not BasePlugin
                        and hasattr(obj, 'name')
                        and obj.name != "base"
                    ):
                        plugin_name = obj.name
                        self._plugins[plugin_name] = obj
                        discovered.append(plugin_name)
                        logger.debug(f"Discovered plugin: {plugin_name} from {module_name}")
            
            except Exception as e:
                logger.warning(f"Failed to load plugin module {module_name}: {e}")
        
        logger.info(f"Discovered {len(discovered)} plugins: {discovered}")
        return discovered
    
    def get_plugin_class(self, name: str) -> Optional[Type[BasePlugin]]:
        """Get a plugin class by name."""
        return self._plugins.get(name)
    
    def get_plugin_instance(
        self,
        name: str,
        config: Optional[Any] = None
    ) -> BasePlugin:
        """
        Get or create a plugin instance.
        
        Args:
            name: Plugin name
            config: Optional configuration to pass to plugin
            
        Returns:
            Plugin instance
            
        Raises:
            PluginLoadException: If plugin not found
        """
        if name in self._instances:
            return self._instances[name]
        
        plugin_class = self._plugins.get(name)
        if not plugin_class:
            raise PluginLoadException(
                f"Plugin not found: {name}",
                plugin_name=name,
            )
        
        try:
            instance = plugin_class(config)
            self._instances[name] = instance
            return instance
        except Exception as e:
            raise PluginLoadException(
                f"Failed to instantiate plugin {name}: {e}",
                plugin_name=name,
                cause=e,
            )
    
    def get_all_plugins(self) -> Dict[str, Type[BasePlugin]]:
        """Get all registered plugin classes."""
        return dict(self._plugins)
    
    def get_plugins_by_category(self, category: str) -> List[Type[BasePlugin]]:
        """Get plugins filtered by category."""
        return [
            plugin for plugin in self._plugins.values()
            if getattr(plugin, 'category', None) == category
        ]
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """
        Get information about all registered plugins.
        
        Returns:
            List of plugin info dictionaries
        """
        plugins_info = []
        
        for name, plugin_class in self._plugins.items():
            info = {
                'name': name,
                'description': getattr(plugin_class, 'description', ''),
                'category': getattr(plugin_class, 'category', 'general'),
                'author': getattr(plugin_class, 'author', 'unknown'),
                'version': getattr(plugin_class, 'version', '1.0.0'),
                'severity': getattr(plugin_class, 'default_severity', 'medium'),
            }
            plugins_info.append(info)
        
        return plugins_info
    
    def unload_plugin(self, name: str) -> bool:
        """
        Unload a plugin instance.
        
        Args:
            name: Plugin name
            
        Returns:
            True if plugin was unloaded
        """
        if name in self._instances:
            del self._instances[name]
            logger.debug(f"Unloaded plugin instance: {name}")
            return True
        return False
    
    def clear(self):
        """Clear all registered plugins and instances."""
        self._plugins.clear()
        self._instances.clear()


# Global registry instance
registry = PluginRegistry()


def discover_plugins() -> List[str]:
    """Discover all available plugins."""
    return registry.discover_plugins()


def get_plugin(name: str, config: Optional[Any] = None) -> BasePlugin:
    """Get a plugin instance by name."""
    return registry.get_plugin_instance(name, config)


def list_plugins() -> List[Dict[str, Any]]:
    """List all available plugins."""
    return registry.list_plugins()


__all__ = [
    "BasePlugin",
    "PluginResult",
    "PluginContext",
    "PluginRegistry",
    "registry",
    "discover_plugins",
    "get_plugin",
    "list_plugins",
]
