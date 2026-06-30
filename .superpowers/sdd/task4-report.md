# Task 4 Report — Migrate All Modules to check_* Methods

**Status: COMPLETE**

## Per-Step Results

| Step | Module | Tests | Status |
|------|--------|-------|--------|
| 1 | configuration/headers.py | 5/5 | PASS |
| 2 | configuration/cookies.py | 5/5 | PASS |
| 3 | configuration/ssl_tls.py | 10/10 | PASS |
| 4 | configuration/cors.py | 5/5 | PASS |
| 5 | configuration/disclosure.py | 6/6 | PASS |
| 6 | configuration/methods.py | 5/5 | PASS |
| 7 | authentication/auth.py | 7/7 | PASS |
| 8 | authentication/authz.py | 3/3 | PASS |
| 9 | authentication/csrf.py | 4/4 | PASS |
| 10 | injection/sqli.py | 3/3 | PASS |
| 11 | injection/xss.py | 3/3 | PASS |
| 11 | injection/nosql.py | 5/5 | PASS |
| 11 | injection/cmd_injection.py | 3/3 | PASS |
| 12 | Full suite (209 tests) | 209/209 | PASS |

## Summary

- **13 module files** migrated with `test()` legacy + `check_*` methods
- All modules keep `discover()` as-is
- Added `SELECTOR_GROUPS` to `auth.py` (`sqli_techniques`) and `sqli.py` (`sqli_techniques`)
- Legacy `test()` methods preserved for `ModuleAdapter` backward compat
- Full suite: **209 passed** in 17.08s
