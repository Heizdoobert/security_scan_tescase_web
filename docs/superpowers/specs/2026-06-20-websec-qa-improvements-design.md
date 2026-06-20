# WebSec Test — QA-Driven Improvements

## Problem Statement

The post-implementation QA review identified 6 high/medium-severity issues across architecture, code quality, test infrastructure, and security. These need structured fixes before the project advances.

## Priority Fixes

### P0 — Thread leak in Timeout decorator
`decorators.py:Timeout.tick()` creates a new `ThreadPoolExecutor` on every call without shutting it down.
**Fix:** Use a persistent executor or `concurrent.futures.wait` with `timeout=` on a single thread.

### P0 — Parallel has no real concurrency
`nodes.py:Parallel.tick()` iterates children sequentially but API implies concurrent execution.
**Fix:** Replace `for child in children` with `ThreadPoolExecutor.map()` (or at minimum document that `min_success` refers to count, not concurrency). **Decision:** Document as synchronous for now — avoiding the thread pool overhead is a deliberate trade-off for Python GIL with I/O-bound checks.

### P1 — Coverage configuration missing
No `[tool.pytest.ini_options]` in `pyproject.toml`, no coverage config.
**Fix:** Add pytest options (test paths, required markers, verbosity) and coverage config (threshold, source paths, report format).

### P1 — Main module loading is fragile
`main.py:64-93` uses a 10-branch if-else chain of deferred imports. Adding a new module requires touching 3 locations.
**Fix:** Replace with a dict-based module registry constructed at module level, keyed by module name.

### P2 — Duplicate form extraction logic
`injection.py` has two identical implementations of `_extract_form_inputs` (one as class method, one as standalone) differing only in return type.
**Fix:** Extract to shared helper returning a consistent dict format, reuse in both places.

### P2 — Stale root-level debug files
`_check_remaining.py`, `_check_urls.py`, `_debug_injection.py`, etc. accumulate in project root from debug sessions.
**Fix:** Clean up. Add `_*.py` to `.gitignore`.

## Excluded from This Round

- Property-based testing (hypothesis): useful but new dependency.
- Mutation testing: tooling setup cost outweighs current benefit.
- ANSI sanitization: target evidence is HTTP body content, rarely contains ANSI codes.
- SAST false-positive reduction: requires AST-level analysis, scope creep.
- Rate limiting: would change observable behavior for real scans; needs design discussion.

## Files Touched

| File | Change |
|------|--------|
| `websec_test/engine/decorators.py` | Persistent ThreadPoolExecutor in Timeout |
| `websec_test/engine/nodes.py` | Document Parallel concurrency semantics |
| `pyproject.toml` | Add pytest + coverage config |
| `websec_test/main.py` | Replace if-else chain with module registry dict |
| `websec_test/modules/injection.py` | Deduplicate _extract_form_inputs |
| `.gitignore` | Add `_*.py` pattern |
| Root directory | Remove `_check_remaining.py`, `_check_urls.py`, etc. |

## Testing Strategy

- All existing 244 tests must still pass after each change
- No new test files needed — all changes are refactoring with preserved behavior
- Thread pool fix: verify via test that repeated Timeout ticks don't leave dangling threads
- Module registry: existing BT integration tests validate module loading paths
