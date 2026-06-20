---
date: 2026-06-17
topic: "Web Security Testing CLI"
status: draft
---

# Web Security Testing CLI — Design Spec

## Problem Statement

A Java web application running at `http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT/` needs automated security testing across common vulnerability categories. The tool should be a lightweight CLI that runs tests and produces structured pass/fail results.

## Constraints

- Target URL is a local development server (no auth beyond basic form-based login)
- No external service dependencies — everything runs locally
- Tests must be non-destructive (read-heavy, no data-modifying payloads unless explicitly enabled)
- Must work on Windows (this dev environment)
- Python 3.x with `requests` as the only heavy dependency

## Approach

**Python CLI with modular test modules.** Each security category is a standalone module with a `discover()` → `test()` pipeline. A shared HTTP client manages session state across all tests. Results flow through a collector into dual output: terminal (real-time colored output) and JSON (structured for analysis/CI).

Chosen over a Node.js approach (heavier deps) and shell-script approach (too fragile for the complexity needed).

## Architecture

```
websec_test/
├── main.py                 # CLI entry point (argparse)
├── client/
│   └── session.py          # requests.Session wrapper
├── modules/
│   ├── __init__.py
│   ├── headers.py          # Security headers, CSP, HSTS
│   ├── auth.py             # Auth bypass, session handling
│   ├── csrf.py             # CSRF token presence & validation
│   ├── injection.py        # SQLi, XSS, command injection
│   └── authz.py            # IDOR, forced browsing, priv escalation
├── results/
│   ├── models.py           # TestResult, Severity, Status enums
│   ├── collector.py        # Aggregate results from all modules
│   └── reporter.py         # Terminal + JSON output
└── config/
    └── payloads.py         # Attack payload dictionaries
```

## Components

### CLI Entry Point (`main.py`)

Uses `argparse`. Flags:
- `--target` (required, str) — base URL
- `--auth` (optional, `user:pass`) — form-based login credentials
- `--modules` (optional, str list or `--all`) — which modules to run
- `--output` (optional, path, default `./reports/`) — output directory
- `--timeout` (optional, int, default 10) — per-request timeout
- `--verbose` / `-v` — increase output verbosity

Validates target is reachable before any tests run.

### HTTP Client (`client/session.py`)

Wraps `requests.Session`:
- Base URL normalization — appends trailing `/` if missing, resolves relative paths
- Cookie jar — automatic persistence across all module requests
- CSRF token extraction — parses HTML responses for `csrf_token`, `_token`, `authenticity_token` by common patterns
- Configurable backoff on 429/503 responses
- Proxy forwarding — `HTTP_PROXY` / `HTTPS_PROXY` env vars respected (for Burp/ZAP debugging)
- Default headers — common User-Agent, Accept, etc.

### Module Protocol

Each module in `modules/` implements:

```python
def discover(session, target) -> list[Endpoint]:
    """Crawl/find testable endpoints. Returns list of discovered targets."""
    ...

def test(session, target, endpoints) -> list[TestResult]:
    """Run tests against discovered endpoints. Returns results."""
    ...
```

**Module: headers.py**
- Checks: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`
- Reports missing headers and their recommended values

**Module: auth.py**
- Tests: login page accessible without auth? blank password? SQLi in username field? session token predictability? logout invalidates session?
- `--auth` flag required to run authenticated session tests

**Module: csrf.py**
- Discovers forms in the target pages
- Checks each form for CSRF token presence
- Tests: token reuse, token validation with modified/replayed token

**Module: injection.py**
- Payload-based: common SQLi patterns (`' OR 1=1--`, `admin'--`), XSS vectors (`<script>alert(1)</script>`, `<img onerror=alert(1)>`), command injection (`; ls`, `| whoami`)
- Tests each discovered endpoint/form field with payloads
- Reports status codes, response time anomalies, reflected content matches

**Module: authz.py**
- Tests: forced browsing (common admin paths: `/admin`, `/config`, `/backup`), IDOR (sequential ID access without auth), vertical privilege escalation attempts
- Requires authenticated session for meaningful results

### Result Models (`results/models.py`)

```python
@dataclass
class TestResult:
    module: str           # e.g. "headers"
    test_name: str        # e.g. "missing_hsts"
    status: str           # "pass" | "fail" | "warn" | "error"
    severity: str         # "critical" | "high" | "medium" | "low" | "info"
    endpoint: str         # URL tested
    evidence: str         # Response excerpt or payload that triggered the finding
    recommendation: str   # What to do about it
```

### Collector (`results/collector.py`)

Accumulates `TestResult` instances from all modules. Provides counts by status and severity. Handles dedup of findings hitting the same endpoint.

### Reporter (`results/reporter.py`)

- **Terminal**: colored output per result (`pass`=green, `fail`=red, `warn`=yellow, `error`=red). Summary table at end: module → total, pass, fail, warn, error.
- **JSON**: structured dump to `{output_dir}/{timestamp}_report.json`. Contains: target, duration, results list, summary stats.

### Payload Library (`config/payloads.py`)

Simple dictionaries keyed by test scenario:
```python
SQLI_PAYLOADS = ["' OR '1'='1", "admin'--", ...]
XSS_PAYLOADS = ["<script>alert(1)</script>", ...]
CMD_INJECT_PAYLOADS = ["; ls", "| whoami", ...]
COMMON_PATHS = ["/admin", "/WEB-INF/web.xml", "/backup", ...]
```

## Data Flow

```
CLI invocation → arg parse → validate target reachable
    │
    ▼
Initialize HTTP client (session, cookies, auth if --auth)
    │
    ▼
For each requested module:
    ├── discover() → endpoint list
    ├── test() → TestResult list → pushed to collector
    │
    ▼
Collector finalizes counts, dedup
    │
    ▼
Reporter writes terminal output + JSON file
```

## Error Handling

| Scenario | Behavior |
|---|---|
| Target unreachable | Error message, exit code 1, no tests run |
| Request timeout | WARN result for that specific test, continue |
| Auth failure | WARN user, run unauthenticated tests anyway |
| Module crash | ERROR result for that module, skip remaining tests in module |
| HTML parse failure | Graceful fallback to raw text matching |
| Non-2xx responses during discovery | Log endpoint as potentially interesting, continue |

All errors are caught at the test level — one failing test never crashes the suite.

## Testing Strategy

- **Unit tests** — `pytest` for each module with mocked HTTP responses (use `responses` or `requests-mock`)
- **Fixture** — a small Flask app with deliberate vulnerabilities (missing headers, open endpoints, reflected XSS) for integration testing
- **Golden file tests** — expected JSON output compared against actual for deterministic modules (headers check)
- **Edge cases** — empty responses, redirect chains, JS-rendered CSRF tokens, non-standard auth forms

## Future Considerations (Out of Scope)

- Browser-level testing (Playwright integration) for DOM-based XSS
- Rate-limiting detection and bypass
- OWASP ZAP/Burp integration
- CI/CD plugin (GitHub Action, GitLab CI template)
- Vulnerability database / CVSS scoring

## Open Questions

- Does the target app use a standard form-based auth, or something custom (JWT, Basic Auth, NTLM)? — This will determine how `--auth` integrates in the first iteration.
