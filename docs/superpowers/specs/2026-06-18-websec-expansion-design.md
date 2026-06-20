---
date: 2026-06-18
topic: "WebSec Test — Expanded Security Coverage"
status: validated
---

## Problem Statement

The existing WebSec Test tool covers 5 security categories (headers, auth, csrf, injection, authz) with ~24 test checks and 53 pytest unit tests. This leaves significant OWASP Top 10 coverage gaps: SSL/TLS misconfiguration, CORS policy issues, cookie security flags, information disclosure, and HTTP verb tampering. The payload dictionaries are also thin — more attack vectors are needed for deeper coverage.

Goal: expand from 5 → 10 modules and 24 → 55+ security checks while keeping zero architectural changes.

## Constraints

- Must follow the existing plugin pattern exactly — no refactoring of the base architecture
- No new Python dependencies beyond `requests`, `pytest`, `responses`
- All tests must use `@responses.activate` mocking — no real network
- Windows-compatible (the project is developed on Windows)
- Non-destructive scanning only (read-heavy, no data-modifying payloads)
- Each test file covers exactly one module

## Approach

Incremental module expansion (Approach 1 from discussion). Add 5 new test modules and deepen 4 existing modules + payloads. No framework changes. No parallel execution — that can come later if needed.

## Architecture

Zero architectural changes. The plugin pattern stays exactly as-is:

```
websec_test/modules/{name}.py → class with discover() + test()
→ registered in main.py (ALL_MODULES + module_map)
→ tests in tests/test_{name}.py using @responses.activate
```

Existing modules get deeper payloads and checks inline. Main.py gets 5 more entries in `ALL_MODULES` and `module_map`.

## Components

### New Modules

#### 1. SSL/TLS (`modules/ssl_tls.py`)

Uses Python stdlib `ssl` + `socket` (no new dependency). Connects to the target host:port and inspects the TLS handshake.

| Test | What It Checks | Severity |
|---|---|---|
| `certificate_valid` | Expired or self-signed certificate error | HIGH |
| `weak_protocol_tls10` | TLS 1.0 enabled | HIGH |
| `weak_protocol_sslv3` | SSLv3 enabled (POODLE) | CRITICAL |
| `hsts_preload` | HSTS header present and includes `preload` | MEDIUM |

Discovery: extracts hostname from target URL, connects on port 443 (or parsed port).

#### 2. CORS (`modules/cors.py`)

Sends requests with `Origin: https://evil.com` and checks response headers.

| Test | What It Checks | Severity |
|---|---|---|
| `wildcard_origin` | `Access-Control-Allow-Origin: *` | HIGH |
| `credentials_with_wildcard` | `Allow-Credentials: true` + wildcard origin | CRITICAL |
| `reflected_origin` | Server echoes back arbitrary Origin | HIGH |
| `missing_cors_validation` | Preflight `OPTIONS` with custom headers succeeds | MEDIUM |

Discovery: sends a GET with a malicious Origin header and inspects response.

#### 3. Cookie Security (`modules/cookies.py`)

Parses `Set-Cookie` headers from root page response for Secure, HttpOnly, SameSite flags.

| Test | What It Checks | Severity |
|---|---|---|
| `missing_secure_flag` | Session cookies without `Secure` on HTTPS | HIGH |
| `missing_httponly_flag` | Cookies accessible via JavaScript | MEDIUM |
| `missing_samesite_flag` | No `SameSite` attribute (CSRF risk) | MEDIUM |
| `persistent_cookies_no_expiry` | Persistent cookies without explicit expiry | LOW |

Discovery: sends GET to `/` and collects all `Set-Cookie` headers.

#### 4. Information Disclosure (`modules/disclosure.py`)

Checks response headers and error pages for information leaks.

| Test | What It Checks | Severity |
|---|---|---|
| `server_version_banner` | `Server` header with version details | MEDIUM |
| `x_powered_by` | `X-Powered-By` header leaks tech stack | LOW |
| `directory_listing` | Accessing `/images/` or `/static/` returns file listing | HIGH |
| `stack_trace_error` | Triggering 404/500 shows stack traces | HIGH |
| `x_asp_net_version` | `X-AspNet-Version` header present | LOW |

Discovery: sends GET to `/`, common dirs, and a nonexistent path.

#### 5. HTTP Methods (`modules/methods.py`)

Probes with non-standard HTTP methods to find exposed operations.

| Test | What It Checks | Severity |
|---|---|---|
| `options_allow_enumeration` | `OPTIONS` reveals allowed methods | MEDIUM |
| `trace_method_enabled` | `TRACE` method enabled (XST attack) | HIGH |
| `put_method_enabled` | `PUT` method allows file uploads | HIGH |
| `delete_method_enabled` | `DELETE` method accessible | HIGH |
| `verb_tampering` | Bypassing auth with alternate HTTP methods | HIGH |

Discovery: sends requests with different HTTP methods to the root and common paths.

### Existing Module Expansions

#### Headers — 3 new checks in `HEADER_CHECKS` dict

| Header | Severity | Recommendation |
|---|---|---|
| `Permissions-Policy` | MEDIUM | Restrict camera/mic/geolocation APIs |
| `Cross-Origin-Opener-Policy` | MEDIUM | Set `same-origin` to isolate cross-origin windows |
| `Cross-Origin-Resource-Policy` | MEDIUM | Set `same-origin` to restrict resource loading |

#### Auth — 2 new test cases

- **Rate-limit detection**: Send 10 rapid POST requests to the login endpoint with bad creds. If none return HTTP 429 or trigger connection reset, emit WARN. If any return 429, PASS.
- **Username enumeration**: Probe 2 valid-looking usernames + 2 invalid ones. Compare response status codes, lengths, and error messages. If responses differ in ways that reveal valid usernames, emit FAIL.

#### Payloads (`config/payloads.py`)

| Payload Type | Additions |
|---|---|
| `SQLI_PAYLOADS` | Time-based: `' OR SLEEP(5)--`, Comment: `admin'--`, Stacked: `'; DROP TABLE users--`, Union: `' UNION SELECT 1,2,3--` |
| `XSS_PAYLOADS` | Polyglot: `jaVasCript:/*-/*`\``/*--></script><img src=x>`, DOM: `</script><script>alert(1)</script>`, Event handler: `<body onload=alert(1)>` |
| `CMD_INJECT_PAYLOADS` | Windows: `& dir`, `| type C:\Windows\win.ini`, Linux: `; id`, `` `ls` `` |
| `COMMON_PATHS` | `/actuator/health`, `/actuator/info`, `/.git/config`, `/jenkins`, `/api/swagger.json`, `/api/v1/`, `/graphql` |

### Main.py Changes

- `ALL_MODULES` grows from 5 to 10 entries
- Module map gets 5 new conditional imports
- The `--modules` argparse `choices` list updates to include new names

## Data Flow

Identical to existing flow:

```
CLI args → main.py → SessionClient(target) → module.discover(client, target)
→ endpoints → module.test(client, target, endpoints) → list[TestResult]
→ ResultCollector.add() → Reporter.to_terminal() + to_json()
```

New modules fit into this pipeline with zero changes to the pipeline itself.

## Error Handling

- **Rate-limit detection**: 429 response = PASS (rate limiting is working correctly). This differs from the existing pattern where 200 with content = PASS.
- **SSL module**: Uses raw sockets. `ssl.SSLError`, `socket.timeout`, `ConnectionRefusedError` all map to `TestResult(status=ERROR)`.
- **Verb tampering**: 200/405 on unexpected methods = FAIL (correct response is 403/401/404).
- **CORS module**: Connection error = WARN rather than ERROR (CORS headers are optional, server may not support them).

All other error handling follows the existing pattern: per-request try/except, module-level failures don't propagate.

## Testing Strategy

New test files:

| Test File | Tests |
|---|---|
| `tests/test_ssl_tls.py` | Valid cert → PASS, expired cert → FAIL, weak TLS → FAIL, connection refused → ERROR |
| `tests/test_cors.py` | No CORS → PASS, wildcard origin → FAIL, creds+wildcard → FAIL, reflected origin → FAIL |
| `tests/test_cookies.py` | Secure+HttpOnly → PASS, bare → FAIL, mixed → WARN |
| `tests/test_disclosure.py` | No server header → PASS, version→FAIL, directory listing→FAIL, error page clean→PASS |
| `tests/test_methods.py` | OPTIONS restricted→PASS, TRACE→FAIL, verb tamper→FAIL, PUT→FAIL |

Each test file uses the `@responses.activate` decorator and asserts `TestResult.status` values.

Existing test file expansions:

| File | New Tests |
|---|---|
| `tests/test_headers.py` | 3 new mock scenarios for Permissions-Policy, COOP, CORP |
| `tests/test_auth.py` | Rate-limit mock (10 requests→1x 429), username enumeration mock |
| `tests/test_payloads.py` | Verify all new payload entries exist and are unique |

## Growth Summary

| Metric | Before | After |
|---|---|---|
| Modules | 5 | 10 |
| Test checks | ~24 | 55+ |
| Payload entries (SQLi+XSS+CMD) | 16 | 30+ |
| Forced-browsing paths | 8 | 14 |
| Pytest tests | 53 | 75+ |

## ✅ Completion Report

**Implemented and verified on 2026-06-18.** All 93 tests passing (91 unit + 2 integration).

### Actual vs Design

| Metric | Designed | Actual |
|---|---|---|
| Modules | 10 | 10 |
| Test checks | 55+ | ~70 individual checks |
| Pytest tests | 75+ | **93** |
| Payload entries (SQLi+XSS+CMD) | 30+ | **33** |
| Forced-browsing paths | 14 | **15** |

### Key Deviations from Design

- **Headers module**: Added CSP/Content-Security-Policy, X-Powered-By, and Server checks instead of Permissions-Policy, COOP, CORP. CSP is a higher-value check for OWASP Top 10 coverage.
- **SSL module**: Added 2 additional HSTS preload tests (present/absent/without-directive), totaling 9 tests instead of the planned 4.
- **Cookies module**: Uses `requests.structures.CaseInsensitiveDict.getlist("Set-Cookie")` instead of simple `resp.headers` iteration to handle multiple Set-Cookie headers correctly.
- **Methods module**: 4th test method `discover_returns_endpoints` added for completeness (not in original design).

### Build Artifacts

- **Design:** `docs/superpowers/specs/2026-06-18-websec-expansion-design.md`
- **Plan:** `thoughts/plans/2026-06-18-websec-expansion-plan.md`
- **Ledger:** `thoughts/ledgers/CONTINUITY_ses_1272.md`

## Open Questions

- **SSL module**: Should we use a raw socket approach or wrap it in SessionClient? Raw socket keeps it dependency-free but can't reuse cookies/sessions. Decision: raw socket via `ssl.SSLContext.wrap_socket()` — this is a one-off connection check, session is irrelevant.
- **Rate-limit threshold**: 10 requests with a 1-second interval is arbitrary. Should this be configurable? Decision: hardcode 10 for now, can be parameterized later if needed.
