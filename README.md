# WebSec Test — Web Security Testing CLI

Automated security testing for web applications and source code. Runs HTTP-based vulnerability checks against a target server, plus standalone SAST, dependency, and compliance scanning. Designed for local development servers and CI pipelines.

## What It Does

Scans a target web app across **10 security modules**:

| Module | What It Checks |
|---|---|
| **Headers** | Missing security headers — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **Auth** | Login form discovery, blank-password acceptance, SQL injection login bypass |
| **CSRF** | POST forms missing CSRF tokens, tokens that can be reused across requests |
| **Injection** | SQLi, XSS, and command injection via reflected payloads in form inputs |
| **Authz** | Forced browsing (open admin/config endpoints), IDOR via sequential user IDs |
| **SSL/TLS** | Certificate expiry, weak protocols (TLS 1.0), HSTS preload readiness |
| **CORS** | Wildcard origins, credential exposure with wildcard, reflected origins |
| **Cookies** | Missing Secure, HttpOnly, and SameSite flags on cookies |
| **Disclosure** | Server banners, directory listing, stack traces on error pages |
| **Methods** | OPTIONS enumeration, TRACE/PUT/DELETE enabled, verb tampering |

Plus a **Senior SecOps Toolkit** (`--secops` flag) with:

- **SAST scan** — pattern-matches source code for hardcoded secrets, SQL injection, XSS, command injection, path traversal, weak crypto, and insecure deserialization
- **Dependency assessment** — parses `requirements.txt`, `pyproject.toml`, `package.json`, `go.mod` and checks against a curated CVE dictionary (no network calls)
- **Compliance check** — scores the project against SOC 2, PCI-DSS, HIPAA, and GDPR control frameworks

And a **MongoDB companion script** for direct database security testing:

- Connection check, authentication status, anonymous access, database enumeration, default credentials, admin user audit

Results appear in the terminal with color-coded pass/fail/warn/error. Structured JSON reports are saved for further analysis.

## Requirements

- Python 3.10+
- `pip install -r requirements.txt` (requests, pytest, responses)
- MongoDB checks require **mongosh** installed (optional — only needed for `mongodb_check.py`)

## Usage

### Web Security Scan

```bash
# Basic scan against your target
python -m websec_test.main --target http://localhost:8080/ --all

# Run only specific modules
python -m websec_test.main --target http://localhost:8080/ --modules headers injection

# With form-based login credentials
python -m websec_test.main --target http://localhost:8080/ --auth admin:password123 --all

# Custom output directory and timeout
python -m websec_test.main --target http://localhost:8080/ --all --output ./results --timeout 15

# With text log output
python -m websec_test.main --target http://localhost:8080/ --all --log scan.log
```

### Senior SecOps Toolkit (SAST + Dependency + Compliance)

```bash
# Run all three phases against a project directory
python -m websec_test.main --secops /path/to/project

# Equivalent standalone scripts
python scripts/security_scanner.py /path/to/project
python scripts/vulnerability_assessor.py /path/to/project
python scripts/compliance_checker.py /path/to/project
```

### MongoDB Security Check

```bash
# Requires mongosh on PATH (or in ./mongosh-bin/)
python -m websec_test.mongodb_check --uri mongodb://localhost:27017

# With explicit mongosh path
python -m websec_test.mongodb_check --uri mongodb://localhost:27017 --mongosh-path "C:\Program Files\MongoDB\Server\8.0\bin\mongosh.exe"

# JSON output
python -m websec_test.mongodb_check --uri mongodb://localhost:27017 --json
```

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--target` | required | Target URL |
| `--auth` | none | Credentials in `user:pass` format |
| `--modules` | all | Space-separated module names: `headers auth csrf injection authz ssl_tls cors cookies disclosure methods` |
| `--all` | false | Run all test modules |
| `--output` | `./reports` | Directory for JSON reports |
| `--timeout` | `10` | Per-request timeout in seconds |
| `--log` | none | Path to write plain-text log |
| `--verbose`, `-v` | false | Increase output verbosity |
| `--secops` | none | Run SAST/dependency/compliance scan on a project directory (defaults to `.`) |

Exit code is **1** if any test fails or errors, **0** otherwise — ready for CI pipelines.

## Output

### Terminal

```
============================================================
  Web Security Test — http://localhost:8080/
============================================================

  [FAIL] headers/check_strict_transport_security
         Endpoint: /
         Evidence: Missing 'Strict-Transport-Security' header
         Fix: Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header

  [PASS] headers/check_x_frame_options
         Endpoint: /
         Evidence: X-Frame-Options: DENY
         Fix: No action needed

  ...

------------------------------------------------------------
  Summary: 60 total  |  PASS: 30  |  FAIL: 20  |  WARN: 7  |  ERROR: 3
============================================================
```

### JSON Report

Saved to `reports/websec_report_20260618_091500.json`:

```json
{
  "target": "http://localhost:8080/",
  "timestamp": "2026-06-18T09:15:00",
  "duration_seconds": 15.2,
  "summary": { "total": 60, "pass": 30, "fail": 20, "warn": 7, "error": 3 },
  "results": [
    {
      "module": "headers",
      "test_name": "check_strict_transport_security",
      "status": "fail",
      "severity": "high",
      "endpoint": "/",
      "evidence": "Missing 'Strict-Transport-Security' header",
      "recommendation": "Add HSTS header with max-age=31536000"
    }
  ]
}
```

## Behavior Tree Engine

Scan execution is powered by a **Behavior Tree engine** (`websec_test/engine/`) that replaces the old linear module loop with a composable, inspectable tree of nodes.

**Key capabilities:**
- **Sequence** — runs modules left-to-right, stops on first failure
- **Selector** — fallback logic (try auth module first, try disclosure only if auth fails)
- **Parallel** — runs independent modules concurrently (with configurable minimum success threshold)
- **Retry** — re-runs a module up to N times with delay
- **Timeout** — enforces a deadline on any module
- **Condition** — gates execution on blackboard state (e.g., skip injection check if no forms found)
- **ModuleAdapter** — wraps any existing module class into a tree node with no code changes

**Pass-through decorators:** Invert, Cooldown, Log — wrap any node without changing its behavior.

Trees are composed in Python code (no config files):

```python
from websec_test.engine import Sequence, Selector, Retry, Parallel, ModuleAdapter
from websec_test.modules.headers import HeadersModule
from websec_test.modules.auth import AuthModule
from websec_test.modules.disclosure import DisclosureModule

root = Sequence("hardened_scan", children=[
    ModuleAdapter("headers", HeadersModule()),
    Retry("auth_retry", max_attempts=3, delay=1,
          child=ModuleAdapter("auth", AuthModule(creds))),
    Selector("fallback", children=[
        ModuleAdapter("disclosure", DisclosureModule()),
        ModuleAdapter("auth", AuthModule(creds)),
    ]),
])
```

Existing module classes (`discover` + `test` pattern) work as-is — `ModuleAdapter` bridges them automatically. No rewrites needed.

## How to Modding

### Adding a New Test Module

1. Create `websec_test/modules/my_module.py`
2. Implement a class with `discover(client, target)` and `test(client, target, endpoints)` methods
3. Register it in `websec_test/main.py` (add to `ALL_MODULES` and the module map)

Example structure:

```python
"""My custom security test module."""
from collections import namedtuple
from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])

class MyModule:
    def discover(self, client: SessionClient, target: str):
        return [Endpoint(url="/", method="GET")]

    def test(self, client: SessionClient, target: str, endpoints):
        results = []
        for ep in endpoints:
            resp = client.get(ep.url)
            results.append(TestResult(
                module="my_module",
                test_name="my_test",
                status=TestStatus.PASS,
                severity=Severity.MEDIUM,
                endpoint=ep.url,
                evidence="Checked ...",
                recommendation="No action needed",
            ))
        return results
```

### Adding Payloads

Edit `websec_test/config/payloads.py`. Add entries to:

- `SQLI_PAYLOADS` — SQL injection strings
- `XSS_PAYLOADS` — Cross-site scripting vectors
- `CMD_INJECT_PAYLOADS` — Command injection patterns
- `NOSQLI_PAYLOADS` — NoSQL injection strings (MongoDB `$ne`, `$gt`, `$regex`)
- `COMMON_PATHS` — Paths for forced browsing checks

### Adding a New Check to an Existing Module

Add a new test case in the module's `test()` method and append a `TestResult`. For headers, add to the `HEADER_CHECKS` dictionary.

## How to Update

### Update Dependencies

```bash
pip install --upgrade -r requirements.txt
```

### Run Tests

```bash
pytest tests/ -v
```

184 tests covering all 10 modules, the session client, collector, reporter, CLI parser, SAST scanner, dependency assessor, compliance checker, MongoDB check, a full integration test, and the behavior tree engine. All HTTP tests mock via the `responses` library — no real network needed.

### Add Tests for a New Module

Create `tests/test_my_module.py` following the pattern of existing test files. Use `@responses.activate` to mock HTTP, and assert `TestResult` status codes.

## Project Structure

```
websec_test/
├── main.py                       # CLI entry point
├── mongodb_check.py              # Companion: MongoDB security checks (via mongosh)
├── client/session.py             # HTTP client (session, cookies, CSRF extraction)
├── modules/
│   ├── headers.py                # Security header checks
│   ├── auth.py                   # Authentication tests
│   ├── csrf.py                   # CSRF token tests
│   ├── injection.py              # SQLi, XSS, command injection, NoSQLi
│   ├── authz.py                  # Forced browsing, IDOR
│   ├── ssl_tls.py                # Certificate, weak protocols, HSTS preload
│   ├── cors.py                   # CORS misconfiguration checks
│   ├── cookies.py                # Cookie security flag checks
│   ├── disclosure.py             # Information disclosure checks
│   └── methods.py                # HTTP verb tampering checks
├── engine/                       # Behavior Tree execution engine
│   ├── __init__.py               # Public API: all node types
│   ├── nodes.py                  # Node ABC, Blackboard, Sequence, Selector, Parallel
│   ├── leaves.py                 # Action, Condition leaf nodes
│   ├── decorators.py             # Retry, Timeout, Invert, Cooldown, Log
│   └── adapters.py               # ModuleAdapter — wraps existing modules
├── security/
│   ├── scanner.py                # SAST pattern scanner (hardcoded secrets, SQLi, XSS, etc.)
│   ├── assessor.py               # Dependency vulnerability assessor (CVE lookup)
│   └── checker.py                # Compliance checker (SOC 2, PCI-DSS, HIPAA, GDPR)
├── results/
│   ├── models.py                 # TestResult dataclass, enums
│   ├── collector.py              # Result aggregation + dedup
│   └── reporter.py               # Terminal + JSON output
└── config/payloads.py            # Attack payload dictionaries

tests/                            # 184 pytest tests
├── test_main.py                  # CLI entry point tests
├── test_session.py               # HTTP client tests
├── test_models.py                # Result model tests
├── test_collector.py             # Collector tests
├── test_reporter.py              # Reporter tests
├── test_payloads.py              # Config/payloads tests
├── test_headers.py               # Header module tests
├── test_auth.py                  # Auth module tests
├── test_csrf.py                  # CSRF module tests
├── test_injection.py             # Injection module tests
├── test_authz.py                 # Authorization module tests
├── test_ssl_tls.py               # SSL/TLS module tests
├── test_cors.py                  # CORS module tests
├── test_cookies.py               # Cookies module tests
├── test_disclosure.py            # Disclosure module tests
├── test_methods.py               # Methods module tests
├── test_scanner.py               # SAST scanner tests
├── test_assessor.py              # Dependency assessor tests
├── test_checker.py               # Compliance checker tests
├── test_mongodb_check.py         # MongoDB check tests
├── test_integration.py           # End-to-end integration test
├── test_bt_nodes.py              # Behavior Tree node tests
├── test_bt_decorators.py         # Behavior Tree decorator tests
├── test_bt_blackboard.py         # Blackboard unit tests
├── test_bt_adapters.py           # ModuleAdapter unit tests
└── test_bt_integration.py        # Behavior Tree integration + regression

scripts/
├── security_scanner.py           # Standalone SAST scanner CLI
├── vulnerability_assessor.py     # Standalone dependency assessor CLI
└── compliance_checker.py         # Standalone compliance checker CLI

docs/superpowers/
├── specs/                        # Design documents
│   ├── 2026-06-17-websec-test-design.md
│   ├── 2026-06-18-websec-expansion-design.md
│   ├── 2026-06-18-mongodb-security-design.md
│   └── 2026-06-19-behavior-tree-design.md
└── plans/                        # Implementation plans
    ├── 2026-06-17-websec-test.md
    └── 2026-06-19-behavior-tree-implementation.md
```

## Notes

- **Non-destructive:** HTTP tests are read-heavy. No data-modifying payloads are sent. MongoDB checks are read-only (via `mongosh --eval`).
- **Windows compatible:** Tested on Windows with Python 3.14.
- **Proxy support:** Respects `HTTP_PROXY` / `HTTPS_PROXY` env vars for Burp/ZAP inspection.
- **External dependency:** MongoDB checks require `mongosh` on PATH (or in `./mongosh-bin/`). Download from [mongodb.com/try/download/shell](https://www.mongodb.com/try/download/shell).
