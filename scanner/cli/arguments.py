"""
Command-line argument parsing for the scanner.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional, List

from scanner import __version__


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    
    parser = argparse.ArgumentParser(
        prog="mwavs",
        description=(
            "MWAVS - Modular Web Application Vulnerability Scanner\n"
            "A production-grade, plugin-driven web security scanner."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://example.com --scan all
  %(prog)s --url https://example.com --scan xss,sqli --threads 20
  %(prog)s --url https://example.com --scan manual
  %(prog)s --url https://example.com --scan dir --output json --verbose

Scan Modes:
  all           Run all available plugins
  manual        Interactive manual testing mode
  xss           Cross-Site Scripting detection
  sqli          SQL Injection detection
  dir           Directory enumeration
  cors          CORS misconfiguration detection
  ssrf          Server-Side Request Forgery detection
  openredirect  Open Redirect detection
        """,
    )
    
    # Required arguments
    required = parser.add_argument_group("Required Arguments")
    required.add_argument(
        "--url", "-u",
        type=str,
        required=True,
        help="Target URL to scan (e.g., https://example.com/page?param=value)",
    )
    
    required.add_argument(
        "--scan", "-s",
        type=str,
        required=True,
        help=(
            "Scan mode: 'all', 'manual', or comma-separated plugin names "
            "(xss,sqli,dir,cors,ssrf,openredirect)"
        ),
    )
    
    # Optional arguments
    optional = parser.add_argument_group("Optional Arguments")
    
    optional.add_argument(
        "--threads", "-t",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)",
    )
    
    optional.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Request timeout in seconds (default: 30)",
    )
    
    optional.add_argument(
        "--proxy", "-p",
        type=str,
        default=None,
        help="Proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)",
    )
    
    optional.add_argument(
        "--output", "-o",
        type=str,
        choices=["json", "html", "txt"],
        default="json",
        help="Output format (default: json)",
    )
    
    optional.add_argument(
        "--output-file", "-of",
        type=str,
        default=None,
        help="Output file path (default: stdout for json/txt, report.html for html)",
    )
    
    optional.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to configuration file (YAML or JSON)",
    )
    
    # Authentication
    auth = parser.add_argument_group("Authentication")
    
    auth.add_argument(
        "--cookie",
        type=str,
        default=None,
        help="Cookie header value (e.g., 'session=abc123; token=xyz')",
    )
    
    auth.add_argument(
        "--header", "-H",
        action="append",
        default=[],
        help="Custom header (can be used multiple times, e.g., -H 'Auth: Bearer token')",
    )
    
    auth.add_argument(
        "--auth-basic",
        type=str,
        default=None,
        metavar="USER:PASS",
        help="HTTP Basic authentication credentials",
    )
    
    # Request options
    request_opts = parser.add_argument_group("Request Options")
    
    request_opts.add_argument(
        "--method", "-m",
        type=str,
        choices=["GET", "POST", "PUT", "DELETE"],
        default="GET",
        help="HTTP method for the target request (default: GET)",
    )
    
    request_opts.add_argument(
        "--data", "-d",
        type=str,
        default=None,
        help="POST data (e.g., 'param1=value1&param2=value2')",
    )
    
    request_opts.add_argument(
        "--json-data",
        type=str,
        default=None,
        help="JSON POST data",
    )
    
    request_opts.add_argument(
        "--user-agent",
        type=str,
        default=None,
        help="Custom User-Agent header",
    )
    
    request_opts.add_argument(
        "--follow-redirects",
        action="store_true",
        default=True,
        help="Follow HTTP redirects (default: True)",
    )
    
    request_opts.add_argument(
        "--no-follow-redirects",
        action="store_true",
        default=False,
        help="Do not follow HTTP redirects",
    )
    
    request_opts.add_argument(
        "--verify-ssl",
        action="store_true",
        default=True,
        help="Verify SSL certificates (default: True)",
    )
    
    request_opts.add_argument(
        "--no-verify-ssl", "-k",
        action="store_true",
        default=False,
        help="Do not verify SSL certificates",
    )
    
    # Scan options
    scan_opts = parser.add_argument_group("Scan Options")
    
    scan_opts.add_argument(
        "--rate-limit",
        type=int,
        default=None,
        help="Maximum requests per second",
    )
    
    scan_opts.add_argument(
        "--delay",
        type=float,
        default=0,
        help="Delay between requests in seconds",
    )
    
    scan_opts.add_argument(
        "--max-payloads",
        type=int,
        default=50,
        help="Maximum payloads per parameter (default: 50)",
    )
    
    scan_opts.add_argument(
        "--stop-on-first",
        action="store_true",
        default=False,
        help="Stop scanning parameter after first finding",
    )
    
    scan_opts.add_argument(
        "--scope",
        type=str,
        action="append",
        default=[],
        help="Additional URLs/patterns in scope",
    )
    
    scan_opts.add_argument(
        "--exclude",
        type=str,
        action="append",
        default=[],
        help="URL patterns to exclude from scanning",
    )
    
    # Wordlists and payloads
    data_opts = parser.add_argument_group("Data Options")
    
    data_opts.add_argument(
        "--wordlist", "-w",
        type=str,
        default=None,
        help="Custom wordlist for directory enumeration",
    )
    
    data_opts.add_argument(
        "--payloads",
        type=str,
        default=None,
        help="Custom payloads file",
    )
    
    # Output options
    output_opts = parser.add_argument_group("Output Options")
    
    output_opts.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Verbose output",
    )
    
    output_opts.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Debug output (very verbose)",
    )
    
    output_opts.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Quiet mode - only show findings",
    )
    
    output_opts.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored output",
    )
    
    output_opts.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Log file path",
    )
    
    # Misc options
    misc = parser.add_argument_group("Miscellaneous")
    
    misc.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    misc.add_argument(
        "--list-plugins",
        action="store_true",
        default=False,
        help="List all available plugins and exit",
    )
    
    misc.add_argument(
        "--update-payloads",
        action="store_true",
        default=False,
        help="Update payload databases and exit",
    )
    
    return parser


def parse_arguments(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = create_argument_parser()
    
    # If no args provided, use sys.argv
    parsed_args = parser.parse_args(args)
    
    # Validate arguments
    _validate_arguments(parsed_args, parser)
    
    return parsed_args


def _validate_arguments(args: argparse.Namespace, parser: argparse.ArgumentParser):
    """Validate parsed arguments."""
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        parser.error("URL must start with http:// or https://")
    
    # Validate scan mode
    valid_modes = {'all', 'manual', 'xss', 'sqli', 'dir', 'cors', 'ssrf', 'openredirect'}
    scan_modes = [m.strip().lower() for m in args.scan.split(',')]
    
    for mode in scan_modes:
        if mode not in valid_modes:
            parser.error(
                f"Invalid scan mode: {mode}. "
                f"Valid modes are: {', '.join(sorted(valid_modes))}"
            )
    
    # Validate threads
    if args.threads < 1:
        parser.error("Threads must be at least 1")
    
    if args.threads > 100:
        parser.error("Threads cannot exceed 100")
    
    # Validate timeout
    if args.timeout <= 0:
        parser.error("Timeout must be positive")
    
    # Validate config file if provided
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            parser.error(f"Configuration file not found: {args.config}")
    
    # Validate wordlist if provided
    if args.wordlist:
        wordlist_path = Path(args.wordlist)
        if not wordlist_path.exists():
            parser.error(f"Wordlist file not found: {args.wordlist}")
    
    # Handle conflicting options
    if args.no_follow_redirects:
        args.follow_redirects = False
    
    if args.no_verify_ssl:
        args.verify_ssl = False