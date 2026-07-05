# Auth-Bypass Test Cases — Design Spec

**Date:** 2026-06-30
**Source:** `D:\Project_1\Nhom_2s\docs\superpowers\specs\auth-bypass-test-cases.xlsx`

## Objective

Replace all existing pytest tests in `tests/` with new test cases that directly mirror the vulnerability scenarios described in the xlsx spec. The xlsx describes a specific vulnerable Java JSP + MongoDB application (`note_webapp_jsp`); the new tests implement those attack types as generic web security tests using the existing `responses` mocking framework.

## Architecture

Six vulnerability groups from the xlsx, mapped to new module files:

| Group | xlsx Sheet | # Scenarios | New Module |
|---|---|---|---|
| Multi-Engine SQL Injection | SQL Injection | 25 | `sqli.py` |
| Multi-Engine NoSQL Injection | Demo, Danh mục | ~8 engines | `nosql.py` |
| Account Takeover | ATO - Quên mật khẩu | 5 | `ato.py` |
| IDOR | IDOR + Leo thang đặc quyền | 2 | `idor.py` |
| Privilege Escalation | IDOR + Leo thang đặc quyền | 10 | `priv_escalation.py` |
| Weak Hashing | Danh mục lỗ hổng | 1 | `hash.py` |

Each module implements: `discover(client, target) → Endpoints` + `test(client, target, endpoints) → list[TestResult]` + BT `CheckSpec` via `@register`.

### Payloads

New `websec_test/config/payloads_sqli.py` — organized by DBMS engine (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, Generic).

Existing `payloads.py` gets `NOSQLI_PAYLOADS` extended to cover MongoDB, CouchDB, Cassandra, DynamoDB, Firebase, Redis, Neo4j.

### Test files

Delete 22 old module test files, create 12 new test files (preserving 17 engine/infra tests). Each module gets:
- 1 standard test file (`test_<module>.py`)
- 1 BT check-level test file (`test_bt_checks_<module>.py`)

Plus 5 infrastructure files: `test_main.py`, `test_session.py`, `test_models.py`, `test_reporter.py`, `test_integration.py`.

## Multi-Engine SQL Injection (`sqli.py`) — 15 checks

Each check probes 6 DBMS engines (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, Generic) with engine-specific syntax.

**Blackboard data flow:** `engine_fingerprint` stores detected DBMS in `blackboard["sqli_engine"]` (e.g. `"mysql"`, `"postgres"`, `"mssql"`, `"oracle"`, `"sqlite"`, `"generic"`). All subsequent checks declare `depends_on=["engine_fingerprint"]` and read `blackboard.get("sqli_engine", "generic")` to select engine-specific payloads.

```python
engine = blackboard.get("sqli_engine", "generic")
payloads = ENGINE_PAYLOADS.get(engine, GENERIC_PAYLOADS)
```

| Check | xlsx TC | depends_on | Multi-Engine Behavior |
|---|---|---|---|
| `engine_fingerprint` | new | (none) | Probes `@@version` (MSSQL), `version()` (MySQL/PG), `SELECT banner FROM v$version` (Oracle). Stores result in `blackboard["sqli_engine"]`. |
| `basic_auth_bypass` | TC-01..03 | `engine_fingerprint` | `' OR '1'='1` (all), `admin'#` (MySQL), last-engine-dependent syntax |
| `error_based` | TC-04..06 | `engine_fingerprint` | `1/0` (MySQL), `CAST(1 AS INT)` (PG), `CONVERT(1, INT)` (MSSQL), `UTL_INADDR` (Oracle) |
| `union_based` | TC-07..08 | `engine_fingerprint` | `ORDER BY N` → `UNION SELECT`. PG: `UNION VALUES` |
| `time_based_blind` | TC-09..10 | `engine_fingerprint` | `SLEEP(5)` (MySQL), `pg_sleep(5)` (PG), `WAITFOR DELAY` (MSSQL), `DBMS_LOCK.SLEEP` (Oracle) |
| `second_order` | TC-11..16 | `engine_fingerprint` | Store `admin'--` via register → trigger via UPDATE. Detect delayed SQL error. |
| `filter_bypass` | TC-17..18 | `engine_fingerprint` | `/**/` as space, `uNiOn` case, `0xHEX` (MySQL), `CHAR()+` (MSSQL), `CHR()` (Oracle) |
| `waf_bypass` | TC-18 | `engine_fingerprint` | HPP (`?id=1&id=UNION`), chunked encoding, JSON body, method switching |
| `header_injection` | TC-19 | `engine_fingerprint` | Inject via User-Agent, Referer, Cookie, X-Forwarded-For |
| `search_injection` | TC-20 | `engine_fingerprint` | LIKE wildcards `%`, `_`, UNION via search, Boolean blind |
| `file_read` | TC-21 | `engine_fingerprint` | `LOAD_FILE()` (MySQL), `pg_read_file()` (PG), `OPENROWSET BULK` (MSSQL) |
| `file_write` | TC-22 | `engine_fingerprint` | `INTO OUTFILE` (MySQL), `COPY TO` (PG), `xp_cmdshell` (MSSQL) |
| `oob_exfil` | TC-23 | `engine_fingerprint` | `LOAD_FILE` via UNC (MySQL), `UTL_HTTP` (Oracle), `dblink` (PG), `xp_dirtree` (MSSQL) |
| `control_param_query` | TC-24 | `engine_fingerprint` | ALL payloads rejected — no SQL errors, no delay |
| `control_input_validation` | TC-25 | (none) | Special chars, long strings, unicode — input stripped/escaped/rejected |

## Multi-Engine NoSQL Injection (`nosql.py`) — 8 checks

| Check | Engine | Payloads |
|---|---|---|
| `nosql_mongodb_auth` | MongoDB | `{"$ne":""}`, `{"$gt":""}`, `{"$regex":".*"}`, `{"$exists":true}`, `{"$where":"sleep(5000)"}` |
| `nosql_mongodb_register_inject` | MongoDB | `test", "role": "SUPERADMIN", "extra": "` |
| `nosql_couchdb` | CouchDB | `{"$gt":null}`, `{"$exists":true}` — selector injection |
| `nosql_cassandra` | Cassandra | `' OR '1'='1`, `' ALLOW FILTERING--` — CQL injection |
| `nosql_dynamodb` | DynamoDB | ExpressionAttributeValues: `{"KeyConditionExpression": "userid = :val AND attribute_exists(#attr)"}`, `{"FilterExpression": "price <> :val"}`, `{"ProjectionExpression": "password"}`. PartiQL: `{"PartiQLStatement": "SELECT * FROM Users WHERE username = 'admin' AND password = 'x'"}` |
| `nosql_firebase` | Firebase | `?auth=admin`, `"priority":{"$ne":null}` |
| `nosql_redis` | Redis | CRLF injection via HTTP params: `key%0D%0AFLUSHALL%0D%0A`, `key%0D%0AEVAL%20%22return%201%22%200%0D%0A`. FRP (false Redis protocol): payload that causes Redis to interpret subsequent bytes as commands. |
| `nosql_cypher` | Neo4j | `' OR 1=1 WITH n RETURN n--` |

## Account Takeover (`ato.py`) — 5 checks

| Check | TC | Steps |
|---|---|---|
| `ato_forgot_password_no_verify` | ATO-1 | POST `/forgot-password` with `username=admin&newPassword=hacked123` → login works |
| `ato_nonexistent_username` | ATO-2 | Reset on nonexistent user → check for username enumeration leaks |
| `ato_old_password_invalidated` | ATO-3 | After reset: old password fails, new password works |
| `ato_superadmin_takeover` | ATO-4 | Take over superadmin → verify role persisted |
| `ato_injected_role_retained` | ATO-5 | Reset injected user → SUPERADMIN role retained |

## IDOR (`idor.py`) — 2 checks

| Check | TC | Steps |
|---|---|---|
| `idor_private_post_read` | IDOR-1 | UserB accesses UserA's `/?_id=<UserA_id>` → private posts leak |
| `idor_private_post_stranger` | IDOR-2 | Unrelated UserD accesses UserC's private posts |

## Privilege Escalation (`priv_escalation.py`) — 9 checks

| Check | TC | Steps |
|---|---|---|
| `pe_admin_panel_hidden_url` | PE-3 | EMPLOYEE accesses `/note/admin?action=listUsers` → blocked |
| `pe_admin_role_param_bypass` | PE-3..4 | Add `&admin_role=SUPERADMIN` → admin panel loads |
| `pe_user_deletion` | PE-4 | Delete user via bypassed admin panel |
| `pe_role_change` | PE-5 | Change user role via bypassed admin panel |
| `pe_self_promotion` | PE-9 | Self-promote EMPLOYEE→SUPERADMIN → persists after re-login (includes register → bypass → self-promote → persist flow) |
| `pe_superadmin_deletion` | PE-11 | Delete superadmin via bypassed admin panel |
| `pe_chain_ato_to_admin` | PE-12 | Reset admin password → login → legitimate admin panel access |
| `pe_role_empty_invalid` | PE-7..8 | `admin_role=` (empty), `admin_role=random` → blocked |

## Weak Hashing (`hash.py`) — 3 checks

| Check | Detection |
|---|---|---|
| `hash_algorithm_detection` | Probe registration/login responses for hash format hints: response headers, hidden form fields, error messages that leak algorithm name. Check for bcrypt (`$2a$`, `$2b$` prefix pattern in any reflected data), SHA-256 (64-char hex), MD5 (32-char hex). |
| `hash_no_salt` | Register same password twice → compare reflected hash. Identical hashes = unsalted → FAIL. Different hashes = salted (or random salt) → PASS. |
| `hash_fast_algorithm` | Based on `hash_algorithm_detection` result: if bcrypt/argon2 detected → PASS (slow). If MD5/SHA-1/SHA-256 detected → FAIL (fast, vulnerable to rainbow tables). If undetermined → WARN (can't verify). Timing-based detection is not used (unreliable with HTTP mocking). |

## Check Dependency Trees

```
# SQLi
engine_fingerprint (root) → basic_auth_bypass → error_based → union_based → file_read/write
                                                → time_based_blind
                                                → second_order
                              → filter_bypass → waf_bypass
                              → header_injection
                              → search_injection
                              → oob_exfil
control_param_query depends on all SQLi checks
control_input_validation (independent)

# NoSQL — all checks independent

# ATO
ato_forgot_password_no_verify → ato_old_password_invalidated, ato_superadmin_takeover, ato_injected_role_retained
ato_nonexistent_username (independent)

# IDOR
idor_private_post_read → idor_private_post_stranger

# PE
pe_admin_role_param_bypass → pe_user_deletion, pe_role_change, pe_self_promotion, pe_superadmin_deletion
pe_admin_panel_hidden_url, pe_role_empty_invalid, pe_chain_ato_to_admin (independent)

# Hash (sequential)
hash_algorithm_detection → hash_no_salt → hash_fast_algorithm
```

## Severity Mapping (xlsx → TestResult)

The xlsx "Danh mục lỗ hổng" sheet assigns severity levels per vulnerability. These map to `Severity` enum:

| xlsx Severity | TestResult Severity | Applies To |
|---|---|---|
| Nghiêm trọng (Critical) | `Severity.CRITICAL` | SQLi injection checks, NoSQL bypass, ATO full takeover, privilege escalation |
| Cao (High) | `Severity.HIGH` | IDOR, stored XSS, forced browsing |
| Trung bình (Medium) | `Severity.MEDIUM` | CSRF, reflected XSS, weak hashing, username enumeration |
| Thấp (Low) | `Severity.LOW` | Schedule ACL, info disclosure |

## Demo Step-by-Step Coverage

The xlsx "Demo (Từng bước cụ thể)" sheet contains 4 detailed A-Z walkthroughs. Each is explicitly covered by a module check:

| Demo # | Scenario | Covered By | Key Assertion |
|---|---|---|---|
| Demo-1 | NoSQL injection via `{"$ne":""}` login bypass | `nosql_mongodb_auth` | `{"$ne":""}` as username+password → authenticated response |
| Demo-2 | ATO via forgot-password — username-only reset | `ato_forgot_password_no_verify` | `/forgot-password` POST accepts username-only → new password works |
| Demo-3 | IDOR — UserB reads UserA's private post via `?_id=` | `idor_private_post_read` | Private post content visible to non-owner |
| Demo-4 | Privilege escalation via register injection (`role: SUPERADMIN` in fullname) | `nosql_mongodb_register_inject` + `pe_self_promotion` | Registered user has SUPERADMIN role, admin panel accessible |

## Files to Delete (21 module test files)

Only module-level tests — BT engine tests and infrastructure tests are preserved (see below).

**Module tests (delete):**
- `test_auth.py`, `test_injection.py`, `test_authz.py`, `test_csrf.py`
- `test_headers.py`, `test_cookies.py`, `test_cors.py`, `test_ssl_tls.py`, `test_disclosure.py`, `test_methods.py`
- `test_mongodb_check.py`, `test_integration.py`
- `test_bt_checks_auth.py`, `test_bt_checks_injection.py`, `test_bt_checks_authz.py`, `test_bt_checks_csrf.py`
- `test_bt_checks_headers.py`, `test_bt_checks_cookies.py`, `test_bt_checks_cors.py`, `test_bt_checks_ssl_tls.py`, `test_bt_checks_disclosure.py`, `test_bt_checks_methods.py`

**Preserve (BT engine tests):**
- `test_bt_nodes.py`, `test_bt_decorators.py`, `test_bt_blackboard.py`, `test_bt_adapters.py`
- `test_bt_builder.py`, `test_bt_check_adapter.py`, `test_bt_registry.py`, `test_bt_integration.py`

**Preserve (infrastructure tests):**
- `test_scanner.py`, `test_assessor.py`, `test_checker.py`, `test_collector.py`, `test_payloads.py`
- `test_session.py`, `test_models.py`, `test_reporter.py`, `test_main.py`

## Files to Create (12 test files + 6 module files + 1 payloads file)

**Modules:** `websec_test/modules/{sqli,nosql,ato,idor,priv_escalation,hash}.py` (6)
**Payloads:** `websec_test/config/payloads_sqli.py` + update `payloads.py`
**Test files (new):** `tests/test_{sqli,nosql,ato,idor,priv_escalation,hash}.py` (6)
**BT test files (new):** `tests/test_bt_checks_{sqli,nosql,ato,idor,priv_escalation,hash}.py` (6)

Infrastructure tests (`test_main`, `test_session`, `test_models`, `test_reporter`, `test_integration`) already exist — preserved, not recreated.
