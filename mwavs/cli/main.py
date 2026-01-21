"""
Main CLI entry point for the scanner.
"""

import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from mwavs import __version__
from mwavs.core.config import ScannerConfig, ScanMode, OutputFormat, ProxyConfig
from mwavs.core.engine import HTTPEngine
from mwavs.core.logger import setup_logging, get_logger
from mwavs.core.utils import URLUtils
from mwavs.core.exceptions import ScannerException, ValidationException
from mwavs.plugins import discover_plugins, get_plugin, list_plugins
from mwavs.plugins.base import PluginContext, PluginResult
from mwavs.reports import JSONReporter, HTMLReporter, TxtReporter
from .arguments import parse_arguments
from .interactive import InteractiveMode


logger = get_logger("main")


def print_banner():
    """Print the scanner banner."""
    banner = r"""
    ╔═══════════════════════════════════════════════════════════╗
    ║   __  ____          _____     _____                       ║
    ║  |  \/  \ \        / / _ \   / ____|                      ║
    ║  | \  / |\ \  /\  / / |_| | | (___   ___ __ _ _ __  ___   ║
    ║  | |\/| | \ \/  \/ /|  _  |  \___ \ / __/ _` | '_ \/ __|  ║
    ║  | |  | |  \  /\  / | | | |  ____) | (_| (_| | | | \__ \  ║
    ║  |_|  |_|   \/  \/  |_| |_| |_____/ \___\__,_|_| |_|___/  ║
    ║                                                           ║
    ║        Modular Web Application Vulnerability Scanner      ║
    ║                      Version 1.0.0                        ║
    ║                      Authon: r0zx                         ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def create_config_from_args(args) -> ScannerConfig:
    """Create ScannerConfig from parsed arguments."""
    config = ScannerConfig()
    
    # Target
    config.target_url = args.url
    
    # Request settings
    config.request.timeout = args.timeout
    config.request.follow_redirects = args.follow_redirects
    config.request.verify_ssl = args.verify_ssl
    
    if args.user_agent:
        config.request.user_agent = args.user_agent
    
    # Parse cookies
    if args.cookie:
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                config.request.cookies[name.strip()] = value.strip()
    
    # Parse headers
    for header in args.header:
        if ':' in header:
            name, value = header.split(':', 1)
            config.request.default_headers[name.strip()] = value.strip()
    
    # Proxy
    if args.proxy:
        config.proxy = ProxyConfig.from_string(args.proxy)
        if args.no_verify_ssl:
            config.proxy.verify_ssl = False
    
    # Concurrency
    config.concurrency.threads = args.threads
    config.concurrency.request_delay = args.delay
    if args.rate_limit:
        config.concurrency.rate_limit = args.rate_limit
    
    # Plugin settings
    config.plugins.max_payloads_per_param = args.max_payloads
    config.plugins.stop_on_first_finding = args.stop_on_first
    
    # Output
    config.report.output_format = OutputFormat(args.output)
    if args.output_file:
        config.report.output_path = Path(args.output_file)
    
    # Logging
    config.verbose = args.verbose
    config.debug = args.debug
    
    if args.log_file:
        config.log_file = Path(args.log_file)
    
    return config


def get_enabled_plugins(args) -> List[str]:
    """Get list of enabled plugins from arguments."""
    scan_modes = [m.strip().lower() for m in args.scan.split(',')]
    
    if 'all' in scan_modes:
        return ['xss', 'sqli', 'dir', 'cors', 'ssrf', 'openredirect']
    
    if 'manual' in scan_modes:
        return []  # Manual mode doesn't use plugins
    
    return scan_modes


def run_scanner(config: ScannerConfig, plugins_to_run: List[str]) -> Dict[str, PluginResult]:
    """Run the scanner with specified configuration and plugins."""
    results = {}
    
    # Create HTTP engine
    with HTTPEngine(config) as engine:
        # Test connection
        logger.info(f"Testing connection to {config.target_url}")
        success, error = engine.test_connection(config.target_url)
        
        if not success:
            raise ScannerException(f"Cannot connect to target: {error}")
        
        logger.info("Connection successful")
        
        # Check for WAF
        waf = engine.detect_waf(config.target_url)
        if waf:
            logger.warning(f"WAF detected: {waf}")
        
        # Get baseline response
        baseline = engine.get_baseline(config.target_url)
        
        # Parse URL for context
        params = URLUtils.get_query_params(config.target_url)
        
        # Create plugin context
        context = PluginContext(
            target_url=config.target_url,
            config=config,
            engine=engine,
            parameters={k: v[0] if len(v) == 1 else v for k, v in params.items()},
            headers=dict(config.request.default_headers),
            cookies=dict(config.request.cookies),
            baseline_response=baseline,
        )
        
        # Discover and load plugins
        discover_plugins()
        
        # Run each plugin
        for plugin_name in plugins_to_run:
            logger.info(f"Running plugin: {plugin_name}")
            
            try:
                plugin = get_plugin(plugin_name, config)
                result = plugin.run(engine, config.target_url, context)
                results[plugin_name] = result
                
                # Log findings
                if result.findings:
                    logger.info(
                        f"Plugin {plugin_name} found {len(result.findings)} issue(s)"
                    )
                    for finding in result.findings:
                        logger.info(
                            f"  [{finding.severity.upper()}] {finding.vulnerability_type}"
                        )
                else:
                    logger.info(f"Plugin {plugin_name} completed with no findings")
            
            except Exception as e:
                logger.error(f"Plugin {plugin_name} failed: {e}")
                results[plugin_name] = PluginResult(
                    plugin_name=plugin_name,
                    errors=[str(e)],
                    completed=False,
                )
    
    return results


def generate_report(
    results: Dict[str, PluginResult],
    config: ScannerConfig,
    scan_duration: float
) -> str:
    """Generate report in specified format."""
    # Aggregate all findings
    all_findings = []
    all_errors = []
    
    for plugin_name, result in results.items():
        all_findings.extend(result.findings)
        all_errors.extend(result.errors)
    
    # Create report data
    report_data = {
        "scan_info": {
            "target": config.target_url,
            "scan_time": datetime.utcnow().isoformat(),
            "duration": scan_duration,
            "plugins_run": list(results.keys()),
            "total_findings": len(all_findings),
            "total_errors": len(all_errors),
        },
        "summary": {
            "critical": len([f for f in all_findings if f.severity == "critical"]),
            "high": len([f for f in all_findings if f.severity == "high"]),
            "medium": len([f for f in all_findings if f.severity == "medium"]),
            "low": len([f for f in all_findings if f.severity == "low"]),
            "info": len([f for f in all_findings if f.severity == "info"]),
        },
        "findings": [f.to_dict() for f in all_findings],
        "errors": all_errors,
        "plugin_results": {
            name: result.to_dict() for name, result in results.items()
        },
    }
    
    # Generate report based on format
    if config.report.output_format == OutputFormat.JSON:
        reporter = JSONReporter()
    elif config.report.output_format == OutputFormat.HTML:
        reporter = HTMLReporter()
    else:
        reporter = TxtReporter()
    
    return reporter.generate(report_data)


def main(args: Optional[List[str]] = None):
    """Main entry point for the scanner."""
    try:
        # Parse arguments
        parsed_args = parse_arguments(args)
        
        # Handle special commands
        if parsed_args.list_plugins:
            discover_plugins()
            print("\nAvailable Plugins:")
            print("-" * 60)
            for plugin_info in list_plugins():
                print(f"  {plugin_info['name']:15} - {plugin_info['description']}")
            return 0
        
        # Print banner (unless quiet mode)
        if not parsed_args.quiet:
            print_banner()
        
        # Create configuration
        config = create_config_from_args(parsed_args)
        
        # Setup logging
        setup_logging(
            level=config.get_log_level(),
            log_file=str(config.log_file) if config.log_file else None,
            use_colors=not parsed_args.no_color,
        )
        
        # Validate target URL
        if not URLUtils.is_valid(config.target_url):
            raise ValidationException(
                f"Invalid target URL: {config.target_url}",
                field="url",
                value=config.target_url,
            )
        
        # Check for manual mode
        if 'manual' in parsed_args.scan.lower():
            logger.info("Starting interactive mode")
            with HTTPEngine(config) as engine:
                interactive = InteractiveMode(engine, config.target_url, config)
                interactive.run()
            return 0
        
        # Get plugins to run
        plugins_to_run = get_enabled_plugins(parsed_args)
        
        if not plugins_to_run:
            logger.error("No plugins selected to run")
            return 1
        
        logger.info(f"Target: {config.target_url}")
        logger.info(f"Plugins: {', '.join(plugins_to_run)}")
        logger.info(f"Threads: {config.concurrency.threads}")
        
        # Run scanner
        start_time = time.time()
        results = run_scanner(config, plugins_to_run)
        scan_duration = time.time() - start_time
        
        # Generate report
        report = generate_report(results, config, scan_duration)
        
        # Output report
        if config.report.output_path:
            with open(config.report.output_path, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to: {config.report.output_path}")
        else:
            print("\n" + report)
        
        # Print summary
        all_findings = []
        for result in results.values():
            all_findings.extend(result.findings)
        
        if not parsed_args.quiet:
            print("\n" + "=" * 60)
            print("SCAN COMPLETE")
            print("=" * 60)
            print(f"Duration: {scan_duration:.2f} seconds")
            print(f"Total findings: {len(all_findings)}")
            
            # Count by severity
            by_severity = {}
            for f in all_findings:
                by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                count = by_severity.get(sev, 0)
                if count > 0:
                    print(f"  {sev.upper()}: {count}")
        
        # Return exit code based on findings
        critical_high = len([f for f in all_findings if f.severity in ('critical', 'high')])
        return 1 if critical_high > 0 else 0
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130
    
    except ScannerException as e:
        logger.error(str(e))
        return 1
    
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

