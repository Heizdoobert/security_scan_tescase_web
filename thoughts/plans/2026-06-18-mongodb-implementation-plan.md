# MongoDB Security Testing — Implementation Plan

**Date:** 2026-06-18
**Based on:** `docs/superpowers/specs/2026-06-18-mongodb-security-design.md`
**Constraints:** No new Python deps, 93 existing tests must pass, no destructive payloads

---

## Batch 1 — Payloads (no dependencies)

### Task 1.1: Add NOSQLI_PAYLOADS to payloads.py

**File:** `websec_test/config/payloads.py`

Add a new `NOSQLI_PAYLOADS` dict after `COMMON_PATHS`. Two categories:

- `"auth_bypass"`: list of 6 payload dicts — `{'$ne': ''}`, `{'$gt': ''}`, `{'$regex': '.*'}`, `{'$in': ['admin']}`, `{'$or': []}`, `{'username': 'admin', 'password': {'$ne': ''}}`
- `"field_injection"`: list of 2 payload dicts — `{'field': {'$gt': ''}}`, `{'$exists': True}`

**Verify:** `python -c "from websec_test.config.payloads import NOSQLI_PAYLOADS; print(len(NOSQLI_PAYLOADS['auth_bypass']), len(NOSQLI_PAYLOADS['field_injection']))"` → `6 2`

### Task 1.2: Add $eval/$where exclusion test to test_payloads.py

**File:** `tests/test_payloads.py` (create if not exists, append if exists)

Create a helper that flattens all values from `NOSQLI_PAYLOADS` (both categories) to strings via `repr()` and asserts that none match `$eval`, `$where`, `$function`, or `$accumulator`.

**Test:** `pytest tests/test_payloads.py -v -k destructive_excluded`

---

## Batch 2 — NoSQL Injection in injection.py (depends on Batch 1)

### Task 2.1: Add _test_nosqli() method to InjectionModule

**File:** `websec_test/modules/injection.py`

**Import change:** Add `NOSQLI_PAYLOADS` to the existing import line from `payloads`.

**New method `_test_nosqli(self, client, target, endpoints)`:**

For each endpoint found via discover:
1. For each param_name in endpoint:
   - **URL-encoded format**: Send `{param_name + '[$ne]': ''}` etc. for auth_bypass payloads
   - **JSON body format**: Send POST with `Content-Type: application/json` and body `{"param_name": {"$ne": ""}}` etc.
   - **Query string format**: Append operator as query param for GET forms
2. After each payload, check response for indicators of bypass:
   - Status 200 with *different* content length than baseline (failed auth response)
   - Response contains "welcome", "dashboard", "login successful", "logged in"
   - Status 500 (server error processing the operator)
3. Create `TestResult` with test_name="nosql_injection", module="injection"
   - If bypass detected: `FAIL`, severity=CRITICAL, evidence shows which payload/format worked
   - If connection error: `ERROR`
   - If no bypass: `PASS`

**Wire into `test()` method:** After the CMD_INJECT block, call `results.extend(self._test_nosqli(client, target, endpoints))`

**Verify:** `python -c "from websec_test.modules.injection import InjectionModule; m=InjectionModule(); assert hasattr(m, '_test_nosqli')"` — no error

### Task 2.2: Add NoSQL injection tests to test_injection.py

**File:** `tests/test_injection.py`

Add these test functions:

1. `test_nosql_payloads_in_form_fields` — Mock a login form, verify payloads are sent (mock responses return 200 with "invalid" text, check all results have test_name="nosql_injection")
2. `test_nosql_bypass_detected` — Mock form, for the operator payload return 200 with "welcome admin" text (different from baseline "invalid password") → assert FAIL
3. `test_nosql_no_bypass` — All responses return "invalid password" consistently → assert PASS
4. `test_nosql_json_body` — Mock a JSON API endpoint that accepts POST with Content-Type: application/json, send JSON-format payloads → assert correct Content-Type sent
5. `test_nosql_query_string` — Mock GET endpoint, verify operator payloads are sent as query params
6. `test_nosql_connection_error` — Mock ConnectionError on payload send → assert ERROR status

All use `@responses.activate` decorator, follow same pattern as existing tests (SessionClient, InjectionModule, discover + test).

**Test:** `pytest tests/test_injection.py -v -k nosql` — all 6 pass

---

## Batch 3 — mongodb_check companion script (no deps on 1-2)

### Task 3.1: Create mongodb_check.py

**File:** `websec_test/mongodb_check.py`

CLI module with `if __name__ == '__main__'` block.

**Functions:**

- `find_mongosh(mongosh_path=None)` → str path or None
  - Ordered checks: explicit arg → `shutil.which('mongosh')` → `os.path.join(os.getcwd(), 'mongosh-bin', 'mongosh.exe')` → glob `C:\Program Files\MongoDB\Server\*\bin\mongosh.exe`
- `run_mongosh_eval(uri, eval_cmd, timeout=5, mongosh_path=None)` → dict (parsed JSON output) or raises
  - `subprocess.run([mongosh_path, '--quiet', '--eval', eval_cmd, uri], capture_output=True, text=True, timeout=timeout)`
  - Returns `json.loads(stdout)`
- `run_all_checks(uri, timeout=5, mongosh_path=None)` → list of result dicts

Six checks, each returns dict `{test_name, status, evidence, recommendation}`:

| Check | mongosh eval | status logic |
|---|---|---|
| connection_check | `JSON.stringify(db.adminCommand('ping'))` | ok → PASS, exception → FAIL |
| auth_status | `JSON.stringify(db.adminCommand({getParameter:1, authenticationMeasures:1}))` | has config → PASS, exception → FAIL |
| anonymous_access | `JSON.stringify(db.adminCommand({listDatabases:1}))` | returns dbs → FAIL (should be blocked), error → PASS |
| database_enumeration | `JSON.stringify(db.adminCommand({listDatabases:1, nameOnly:true}))` | names returned → FAIL, error → PASS |
| default_credentials | Try auth with `admin:admin`, `root:root` | any succeeds → FAIL, all fail → PASS |
| admin_users | `JSON.stringify(db.getSiblingDB('admin').system.users.find().toArray())` | has users → WARN, empty → PASS |

- `print_terminal(results)` — color-coded table
- `write_json_report(results)` — writes `mongodb_report_YYYYMMDD_HHMMSS.json` to cwd

**CLI argument parsing** (argparse):
- `--uri` (required, default `mongodb://localhost:27017`)
- `--timeout` (int, default 5)
- `--json` (flag, outputs machine-parseable JSON to stdout)
- `--mongosh-path` (optional, explicit path)

**Verify:** `python -m websec_test.mongodb_check --help` shows all flags

### Task 3.2: Create test_mongodb_check.py

**File:** `tests/test_mongodb_check.py`

Use `unittest.mock.patch('subprocess.run')` to mock mongosh responses.

10 test functions:

| Test | What it mocks | Assertion |
|---|---|---|
| `test_ping_success` | subprocess returns `{"ok": 1}` | PASS status |
| `test_ping_connection_refused` | subprocess raises `subprocess.CalledProcessError` | FAIL status |
| `test_auth_enabled` | returns `{"authenticationMeasures": 1}` | PASS |
| `test_anonymous_access` | returns `{"databases": [{"name": "admin"}]}` | FAIL (anonymous access allowed) |
| `test_anonymous_blocked` | raises "not authorized" | PASS (auth required) |
| `test_default_creds_valid` | first connect attempt succeeds | FAIL |
| `test_default_creds_rejected` | all attempts fail | PASS |
| `test_admin_users_detected` | returns `[{"user": "admin"}]` | WARN |
| `test_mongosh_not_found` | `find_mongosh()` returns `None` | gracefully exits with error message |
| `test_timeout` | subprocess raises `TimeoutExpired` | ERROR status |
| `test_json_output_flag` | runs `run_all_checks` with mocked subprocess, `--json` flag | valid JSON structure |

**Verify:** `pytest tests/test_mongodb_check.py -v` — all 11 pass

---

## Batch 4 — Integration verification (depends on all above)

### Task 4.1: Run full test suite

```bash
pytest tests/ -v 2>&1
```

**Expected:** All ~110 tests pass (93 existing + 6 NoSQLi + 11 mongodb_check).

### Task 4.2: Verify import chain works

```bash
python -c "from websec_test.config.payloads import NOSQLI_PAYLOADS; print('payloads OK')"
python -c "from websec_test.modules.injection import InjectionModule; print('injection OK')"
python -c "from websec_test.mongodb_check import run_all_checks, find_mongosh; print('mongodb_check OK')"
```

All three should print their "OK" message without ImportError.

---

## Execution Order

```
Batch 1 ──→ Batch 2 ──→ Batch 4
  │                      │
  └──────────────────────┤
                         │
Batch 3 ─────────────────┘
```

- Batch 1 and Batch 3 can run in parallel (no shared deps)
- Batch 2 depends on Batch 1
- Batch 4 depends on Batch 2 + Batch 3

## Files Changed Summary

| File | Action | Lines estimate |
|---|---|---|
| `websec_test/config/payloads.py` | Modify (+NOSQLI_PAYLOADS) | +20 lines |
| `websec_test/modules/injection.py` | Modify (+_test_nosqli, import) | +60 lines |
| `websec_test/mongodb_check.py` | Create | +180 lines |
| `tests/test_payloads.py` | Modify (+exclusion test) | +15 lines |
| `tests/test_injection.py` | Modify (+6 NoSQLi tests) | +90 lines |
| `tests/test_mongodb_check.py` | Create | +150 lines |

**Total: ~515 lines added, 0 lines removed, 6 files touched (3 new, 3 modified)**
