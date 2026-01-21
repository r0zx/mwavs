"""
Interactive mode for manual testing.
Provides a CLI menu for request crafting and payload testing.
"""

import sys
import json
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse, urlencode, parse_qs

from scanner.core.engine import HTTPEngine
from scanner.core.config import ScannerConfig
from scanner.core.request_wrapper import RequestWrapper, HTTPMethod, RequestBuilder
from scanner.core.response_wrapper import ResponseWrapper
from scanner.core.logger import get_logger
from scanner.core.utils import PayloadEncoder

logger = get_logger("interactive")


class InteractiveMode:
    """
    Interactive CLI mode for manual security testing.
    
    Features:
    - Request method selection
    - Parameter/header/cookie editing
    - Payload execution
    - Raw response viewing
    - Request history
    """
    
    def __init__(self, engine: HTTPEngine, target_url: str, config: ScannerConfig):
        self.engine = engine
        self.target_url = target_url
        self.config = config
        
        # Parse initial URL
        parsed = urlparse(target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.query_params = {}
        for key, values in parse_qs(parsed.query).items():
            self.query_params[key] = values[0] if len(values) == 1 else values
        
        # Request components
        self.method = HTTPMethod.GET
        self.headers: Dict[str, str] = {
            "User-Agent": config.request.user_agent,
        }
        self.cookies: Dict[str, str] = {}
        self.body_data: Dict[str, str] = {}
        self.json_body: Optional[Dict] = None
        
        # History
        self.request_history: List[Dict] = []
        self.response_history: List[ResponseWrapper] = []
    
    def run(self):
        """Run the interactive mode."""
        self._print_banner()
        self._print_help()
        
        while True:
            try:
                command = input("\n[MWAVS]> ").strip()
                
                if not command:
                    continue
                
                if command.lower() in ('quit', 'exit', 'q'):
                    print("\n[*] Exiting interactive mode...")
                    break
                
                self._process_command(command)
            
            except KeyboardInterrupt:
                print("\n[*] Use 'quit' or 'exit' to exit.")
            
            except EOFError:
                print("\n[*] Exiting...")
                break
            
            except Exception as e:
                print(f"[!] Error: {e}")
                logger.error(f"Interactive mode error: {e}", exc_info=True)
    
    def _print_banner(self):
        """Print interactive mode banner."""
        print("\n" + "=" * 60)
        print("  MWAVS Interactive Mode - Manual Security Testing")
        print("=" * 60)
        print(f"  Target: {self.target_url}")
        print("=" * 60)
    
    def _print_help(self):
        """Print help message."""
        help_text = """
Available Commands:
  help, h, ?        Show this help message
  
Request Configuration:
  method <GET|POST|PUT|DELETE>  Set HTTP method
  param <name> <value>          Set URL parameter
  header <name> <value>         Set HTTP header
  cookie <name> <value>         Set cookie
  data <name> <value>           Set POST body parameter
  json <json_string>            Set JSON body
  url <new_url>                 Change target URL
  
Request Actions:
  send, go, s       Send the current request
  raw               Show raw request that will be sent
  clear             Clear all parameters and headers
  
Payloads:
  payload xss <param>           Test XSS payloads on parameter
  payload sqli <param>          Test SQLi payloads on parameter
  encode <type> <string>        Encode string (url, html, base64)
  
Response:
  response, resp    Show last response
  headers           Show last response headers
  body              Show last response body
  status            Show last response status
  
History:
  history           Show request history
  replay <number>   Replay request from history
  
Other:
  quit, exit, q     Exit interactive mode
"""
        print(help_text)
    
    def _process_command(self, command: str):
        """Process a user command."""
        parts = command.split(None, 2)
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        commands = {
            'help': self._print_help,
            'h': self._print_help,
            '?': self._print_help,
            'method': lambda: self._set_method(args),
            'param': lambda: self._set_param(args),
            'header': lambda: self._set_header(args),
            'cookie': lambda: self._set_cookie(args),
            'data': lambda: self._set_data(args),
            'json': lambda: self._set_json(args),
            'url': lambda: self._set_url(args),
            'send': self._send_request,
            'go': self._send_request,
            's': self._send_request,
            'raw': self._show_raw_request,
            'clear': self._clear_request,
            'payload': lambda: self._test_payload(args),
            'encode': lambda: self._encode_string(args),
            'response': self._show_response,
            'resp': self._show_response,
            'headers': self._show_response_headers,
            'body': self._show_response_body,
            'status': self._show_response_status,
            'history': self._show_history,
            'replay': lambda: self._replay_request(args),
        }
        
        if cmd in commands:
            result = commands[cmd]
            if callable(result):
                result()
        else:
            print(f"[!] Unknown command: {cmd}. Type 'help' for available commands.")
    
    def _set_method(self, args: List[str]):
        """Set HTTP method."""
        if not args:
            print(f"[*] Current method: {self.method.value}")
            return
        
        method = args[0].upper()
        try:
            self.method = HTTPMethod(method)
            print(f"[+] Method set to: {method}")
        except ValueError:
            print(f"[!] Invalid method: {method}. Use GET, POST, PUT, or DELETE.")
    
    def _set_param(self, args: List[str]):
        """Set URL parameter."""
        if len(args) < 2:
            print("[*] Current parameters:")
            for k, v in self.query_params.items():
                print(f"    {k} = {v}")
            print("\n[!] Usage: param <name> <value>")
            return
        
        name = args[0]
        value = args[1] if len(args) > 1 else ""
        self.query_params[name] = value
        print(f"[+] Parameter set: {name} = {value}")
    
    def _set_header(self, args: List[str]):
        """Set HTTP header."""
        if len(args) < 2:
            print("[*] Current headers:")
            for k, v in self.headers.items():
                print(f"    {k}: {v}")
            print("\n[!] Usage: header <name> <value>")
            return
        
        name = args[0]
        value = " ".join(args[1:])
        self.headers[name] = value
        print(f"[+] Header set: {name}: {value}")
    
    def _set_cookie(self, args: List[str]):
        """Set cookie."""
        if len(args) < 2:
            print("[*] Current cookies:")
            for k, v in self.cookies.items():
                print(f"    {k} = {v}")
            print("\n[!] Usage: cookie <name> <value>")
            return
        
        name = args[0]
        value = args[1]
        self.cookies[name] = value
        print(f"[+] Cookie set: {name} = {value}")
    
    def _set_data(self, args: List[str]):
        """Set POST body parameter."""
        if len(args) < 2:
            print("[*] Current body data:")
            for k, v in self.body_data.items():
                print(f"    {k} = {v}")
            print("\n[!] Usage: data <name> <value>")
            return
        
        name = args[0]
        value = " ".join(args[1:])
        self.body_data[name] = value
        print(f"[+] Body data set: {name} = {value}")
    
    def _set_json(self, args: List[str]):
        """Set JSON body."""
        if not args:
            print(f"[*] Current JSON body: {json.dumps(self.json_body)}")
            print("\n[!] Usage: json <json_string>")
            return
        
        try:
            json_str = " ".join(args)
            self.json_body = json.loads(json_str)
            print(f"[+] JSON body set: {json.dumps(self.json_body, indent=2)}")
        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON: {e}")
    
    def _set_url(self, args: List[str]):
        """Change target URL."""
        if not args:
            print(f"[*] Current URL: {self.base_url}")
            return
        
        new_url = args[0]
        if not new_url.startswith(('http://', 'https://')):
            new_url = f"https://{new_url}"
        
        parsed = urlparse(new_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Update query params if present
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                self.query_params[key] = values[0] if len(values) == 1 else values
        
        print(f"[+] URL set to: {new_url}")
    
    def _build_request(self) -> RequestWrapper:
        """Build request from current configuration."""
        builder = RequestBuilder(self.base_url).method(self.method)
        
        if self.query_params:
            builder.params(self.query_params)
        
        if self.headers:
            builder.headers(self.headers)
        
        if self.cookies:
            builder.cookies(self.cookies)
        
        if self.json_body:
            builder.json(self.json_body)
        elif self.body_data:
            builder.data(self.body_data)
        
        return builder.build()
    
    def _send_request(self):
        """Send the current request."""
        try:
            request = self._build_request()
            
            print(f"\n[*] Sending {request.method.value} request to {request.build_full_url()}...")
            
            response = self.engine.request(request)
            
            # Store in history
            self.request_history.append({
                'url': request.build_full_url(),
                'method': request.method.value,
                'headers': dict(request.headers),
                'params': dict(request.params),
                'data': request.data,
            })
            self.response_history.append(response)
            
            # Print summary
            print(f"\n[+] Response received:")
            print(f"    Status: {response.status_code}")
            print(f"    Length: {response.content_length} bytes")
            print(f"    Time: {response.elapsed_time:.3f}s")
            print(f"    Content-Type: {response.content_type or 'N/A'}")
            
            if response.is_redirect:
                print(f"    Location: {response.location}")
            
            print(f"\n[*] Use 'response' to see full response, 'body' for body only.")
        
        except Exception as e:
            print(f"[!] Request failed: {e}")
    
    def _show_raw_request(self):
        """Show raw HTTP request."""
        request = self._build_request()
        print("\n" + "=" * 50)
        print("RAW HTTP REQUEST")
        print("=" * 50)
        print(request.to_raw_http())
        print("=" * 50)
        
        print("\n[*] cURL equivalent:")
        print(request.to_curl())
    
    def _clear_request(self):
        """Clear all request parameters."""
        self.query_params.clear()
        self.headers = {"User-Agent": self.config.request.user_agent}
        self.cookies.clear()
        self.body_data.clear()
        self.json_body = None
        self.method = HTTPMethod.GET
        print("[+] Request configuration cleared.")
    
    def _test_payload(self, args: List[str]):
        """Test payloads on a parameter."""
        if len(args) < 2:
            print("[!] Usage: payload <type> <param_name>")
            print("    Types: xss, sqli")
            return
        
        payload_type = args[0].lower()
        param_name = args[1]
        
        if payload_type not in ('xss', 'sqli'):
            print(f"[!] Unknown payload type: {payload_type}")
            return
        
        # Simple payloads for testing
        payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                "'-alert(1)-'",
            ],
            'sqli': [
                "'",
                "' OR '1'='1",
                "1' AND '1'='1",
                "1; DROP TABLE users--",
            ],
        }
        
        print(f"\n[*] Testing {payload_type.upper()} payloads on parameter: {param_name}")
        
        for payload in payloads[payload_type]:
            # Save original value
            original = self.query_params.get(param_name, '')
            
            # Set payload
            self.query_params[param_name] = payload
            
            try:
                request = self._build_request()
                response = self.engine.request(request)
                
                # Check for reflection (XSS) or errors (SQLi)
                indicator = ""
                if payload_type == 'xss' and payload in response.text:
                    indicator = " [REFLECTED!]"
                elif payload_type == 'sqli':
                    error_patterns = ['sql', 'syntax', 'error', 'mysql', 'postgresql']
                    if any(p in response.text.lower() for p in error_patterns):
                        indicator = " [SQL ERROR!]"
                
                print(f"    [{response.status_code}] {payload[:40]}...{indicator}")
            
            except Exception as e:
                print(f"    [ERROR] {payload[:40]}... - {e}")
            
            finally:
                # Restore original value
                self.query_params[param_name] = original
    
    def _encode_string(self, args: List[str]):
        """Encode a string."""
        if len(args) < 2:
            print("[!] Usage: encode <type> <string>")
            print("    Types: url, html, base64, unicode, hex")
            return
        
        encode_type = args[0].lower()
        string = " ".join(args[1:])
        
        encoders = {
            'url': PayloadEncoder.url_encode,
            'html': PayloadEncoder.html_encode,
            'base64': PayloadEncoder.base64_encode,
            'unicode': PayloadEncoder.unicode_encode,
            'hex': PayloadEncoder.hex_encode,
        }
        
        if encode_type not in encoders:
            print(f"[!] Unknown encoding type: {encode_type}")
            return
        
        encoded = encoders[encode_type](string)
        print(f"\n[+] {encode_type.upper()} encoded:")
        print(f"    Original: {string}")
        print(f"    Encoded:  {encoded}")
    
    def _show_response(self):
        """Show last response."""
        if not self.response_history:
            print("[!] No response in history. Send a request first.")
            return
        
        response = self.response_history[-1]
        print("\n" + "=" * 50)
        print("LAST RESPONSE")
        print("=" * 50)
        print(response.to_raw_http())
        print("=" * 50)
    
    def _show_response_headers(self):
        """Show last response headers."""
        if not self.response_history:
            print("[!] No response in history.")
            return
        
        response = self.response_history[-1]
        print(f"\n[*] Response Headers (Status: {response.status_code}):")
        for key, value in response.headers.items():
            print(f"    {key}: {value}")
    
    def _show_response_body(self):
        """Show last response body."""
        if not self.response_history:
            print("[!] No response in history.")
            return
        
        response = self.response_history[-1]
        print(f"\n[*] Response Body ({response.content_length} bytes):")
        print("-" * 50)
        
        # Limit output
        body = response.text
        if len(body) > 5000:
            print(body[:5000])
            print(f"\n... [truncated, {len(body) - 5000} more bytes]")
        else:
            print(body)
    
    def _show_response_status(self):
        """Show last response status."""
        if not self.response_history:
            print("[!] No response in history.")
            return
        
        response = self.response_history[-1]
        print(f"\n[*] Status: {response.status_code}")
        print(f"    Time: {response.elapsed_time:.3f}s")
        print(f"    Length: {response.content_length} bytes")
    
    def _show_history(self):
        """Show request history."""
        if not self.request_history:
            print("[!] No requests in history.")
            return
        
        print("\n[*] Request History:")
        for i, req in enumerate(self.request_history, 1):
            resp = self.response_history[i-1]
            print(f"    [{i}] {req['method']} {req['url'][:60]} -> {resp.status_code}")
    
    def _replay_request(self, args: List[str]):
        """Replay a request from history."""
        if not args:
            print("[!] Usage: replay <number>")
            return
        
        try:
            index = int(args[0]) - 1
            if 0 <= index < len(self.request_history):
                req = self.request_history[index]
                
                # Restore request configuration
                self.base_url = req['url'].split('?')[0]
                self.method = HTTPMethod(req['method'])
                self.headers = req['headers']
                self.query_params = req['params']
                self.body_data = req.get('data', {}) or {}
                
                print(f"[+] Loaded request #{index + 1}")
                self._send_request()
            else:
                print(f"[!] Invalid history number. Use 1-{len(self.request_history)}")
        
        except ValueError:
            print("[!] Invalid number.")