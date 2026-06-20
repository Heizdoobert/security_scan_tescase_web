# MongoDB Security Testing — Design Doc

**Date:** 2026-06-18
**Status:** Draft
**Project:** WebSec Test CLI
**Author:** brainstormer → design

---

## 1. Problem Statement

The WebSec Test tool currently scans web apps via HTTP across 10 security modules. The target at `D:\Project_1` uses **MongoDB** as its backend database (running on `localhost:27017`, database `note_webapp_jsp`, **no authentication enabled**). The tool has no ability to:

- Test for NoSQL injection through HTTP endpoints
- Verify MongoDB authentication status or default credentials
- Enumerate MongoDB databases/collections for exposure

We need to add both capabilities while keeping the tool focused and following existing patterns.

---

## 2. Constraints

- **No new Python dependencies** — mongosh (already at `D:\Project_1\mongosh-bin\mongosh.exe`) is the only external tool we shell out to. All other changes use stdlib.
- **93 existing tests must still pass** — no breaking changes to existing code.
- **No destructive payloads** — `$eval`, `$where`, `$function` are explicitly excluded from NoSQL injection payloads.
- **Report format compatibility** — new modules output must match the existing `TestResult` schema.
- **The main tool stays HTTP-focused** — direct MongoDB checks are a companion script, not part of the main pipeline.

---

## 3. Approach

### Two separate concerns, two different mechanisms

| Concern | Mechanism | Where it lives |
|---|---|---|
| **NoSQL injection** via HTTP | Extends existing `injection.py` with MongoDB-specific payloads | Inside the main scan pipeline (same `--target`, same `SessionClient`) |
| **Direct MongoDB auth/perms** | Companion script using `subprocess` + `mongosh` | Standalone: `python -m websec_test.mongodb_check --uri mongodb://...` |

**Why split:** The main scanner is HTTP-only. Adding direct DB protocol support would break the clean `discover/test` module pattern and require a new client interface. NoSQL injection *does* belong in the HTTP scan — it's an attack vector via form fields and JSON bodies, just with MongoDB-specific payloads.

---

## 4. Architecture

### Dependency Graph

```
injection.py ──→ payloads.py     (existing, +NOSQLI_PAYLOADS)
         │
         └──→ SessionClient      (existing, reused)
         │
         └──→ TestResult         (existing, reused)

mongodb_check.py ──→ subprocess  (stdlib only)
              │
              └──→ mongosh       (external binary, optional at runtime)
```

No circular dependencies. No coupling between the two additions.

### Files Changed

**Modified:**
- `websec_test/config/payloads.py` — Add `NOSQLI_PAYLOADS` dict (6 payload categories)
- `websec_test/modules/injection.py` — Add `_test_nosqli()` method
- `tests/test_injection.py` — Add 6-8 NoSQL injection test cases

**Created:**
- `websec_test/mongodb_check.py` — Standalone companion script
- `tests/test_mongodb_check.py` — ~10 tests mocking subprocess.run

**Not changed:**
- `main.py`, `results/models.py`, `results/collector.py`, `results/reporter.py`, `client/session.py`
- All 10 existing module files
- All existing test files (93 tests untouched)

---

## 5. Component Design

### 5.1 Payloads (`payloads.py`)

New `NOSQLI_PAYLOADS` dict with two categories:

**Authentication bypass** (for login forms):
- `{'$ne': ''}` — "not equal to empty" matches everything
- `{'$gt': ''}` — "greater than empty" match
- `{'$regex': '.*'}` — regex wildcard
- `{'$in': ['admin']}` — array match
- `{'$or': []}` — empty OR clause
- Nested formats: `{'username': 'admin', 'password': {'$ne': ''}}`

**Field injection** (for search/query endpoints):
- `{'field': {'$gt': ''}}` — query string operator
- `{'$exists': True}` — field existence

**Explicitly excluded** (safety):
- `$eval`, `$where`, `$function`, `$accumulator`

### 5.2 NoSQL Injection (`injection.py`)

New `_test_nosqli()` method alongside existing `_test_sqli()` / `_test_xss()` / `_test_cmd_injection()`:

1. Discovers forms via existing `_discover_forms()` helper
2. For each form field, sends payloads in three formats:
   - **URL-encoded**: `username[$ne]=` (PHP-style parameter parsing)
   - **JSON body**: `{"username": {"$ne": ""}}` (for JSON API endpoints)
   - **Query string**: appended to GET action URLs
3. Checks for successful bypass (different response than failed auth)
4. Returns `TestResult` list with module=`injection`, test_name=`nosql_injection`

### 5.3 Companion Script (`mongodb_check.py`)

CLI entry point:

```
python -m websec_test.mongodb_check --uri mongodb://localhost:27017
```

Optional flags:
- `--json` — Output to stdout in JSON format; also writes a report file named `mongodb_report_YYYYMMDD_HHMMSS.json` to the current directory (follows same field names as main scan reports)
- `--timeout` — Seconds to wait for mongosh response (default: 5)
- `--mongosh-path` — Explicit path to mongosh binary (default: auto-detect in this order: (1) `shutil.which('mongosh')` for PATH, (2) `.\mongosh-bin\mongosh.exe`, (3) `C:\Program Files\MongoDB\Server\*\bin\mongosh.exe`, (4) fallback locations common on the platform)

Six test scenarios via mongosh subprocess:

| Test | mongosh command |
|---|---|
| Connection check | `db.adminCommand('ping')` |
| Auth status | `db.adminCommand({getParameter:1, authenticationMeasures:1})` |
| Anonymous access | `db.adminCommand({listDatabases:1})` |
| Database enumeration | `db.adminCommand({listDatabases:1, nameOnly:true})` |
| Default creds | Connect with `admin:admin`, `root:root`, etc. |
| Admin user check | `db.getSiblingDB('admin').system.users.find()` |

---

## 6. Data Flow

### NoSQL Injection Flow

```
main.py (CLI)
  → injection.py (module)
    → _discover_forms() using SessionClient
    → _test_nosqli() for each form/endpoint
      → Send payloads (URL-encoded / JSON / query string)
      → Compare response to baseline (failed auth response)
      → Create TestResult[]
  → returned to collector → reporter
```

### mongodb_check Flow

```
mongodb_check.py (CLI)
  → Parse --uri, --timeout, --json flags
  → For each test scenario:
    → subprocess.run(['mongosh', '--quiet', '--eval', ..., uri])
    → Parse JSON output from mongosh
    → Create result dict {test_name, status, evidence, recommendation}
  → Terminal output (color-coded)
  → Optional JSON report file
```

---

## 7. Error Handling

### NoSQL Injection

- Wraps payload attempts in try/except, returns `TestResult(status=ERROR)` on exception
- 500 responses → `FAIL` with evidence of server-side error
- Connection errors handled by `SessionClient` (existing behavior)

### mongodb_check

| Scenario | Result |
|---|---|
| mongosh not found | `ERROR` — "Install MongoDB Shell" |
| Connection refused | `FAIL` — "Connection refused on {uri}" |
| Auth with creds fails | `PASS` — "Authentication required" |
| Auth without creds succeeds | `FAIL` — "No authentication required" |
| Timeout | `ERROR` — "Connection timed out" |

---

## 8. Testing Strategy

### NoSQL Injection Tests (6-8 tests, `responses` library)

| Test | Scenario |
|---|---|
| `test_nosql_payloads_in_form_fields` | Mock form, verify payloads sent |
| `test_nosql_bypass_detected` | Successful auth on payload → FAIL |
| `test_nosql_no_bypass` | Failed auth → PASS |
| `test_nosql_json_body` | JSON endpoint with operator payload |
| `test_nosql_query_string` | GET with operator in query string |
| `test_nosql_connection_error` | Connection failure → ERROR |
| `test_nosql_destructive_excluded` | `$eval`/`$where` not in payloads |

### mongodb_check Tests (~10 tests, `unittest.mock.patch`)

| Test | Scenario |
|---|---|
| `test_ping_success` | mongosh returns ping response |
| `test_ping_connection_refused` | subprocess raises exception |
| `test_auth_enabled` | Shows authentication measures |
| `test_anonymous_access` | listDatabases returns data |
| `test_default_creds_valid` | Connects with admin:admin |
| `test_default_creds_rejected` | Auth fails |
| `test_admin_users_detected` | system.users has entries |
| `test_mongosh_not_found` | FileNotFoundError |
| `test_timeout` | Subprocess timeout |
| `test_json_output` | `--json` flag produces valid JSON |

---

## 9. Open Questions

None — all design decisions made.
