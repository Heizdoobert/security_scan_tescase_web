# Task 2 Report: CheckAdapter + CheckTreeBuilder

## Status: COMPLETE

## Commits
- `269f355` — "feat: add CheckAdapter, CheckTreeBuilder for check-level BT"

## Files changed
| File | Action |
|------|--------|
| `websec_test/engine/adapters.py` | Modified — added `CheckAdapter` (Action leaf wrapping a check function) |
| `websec_test/engine/builder.py` | Modified — `CheckTreeBuilder.build` as `@staticmethod`, scans `check_*` methods, supports `SELECTOR_GROUPS`, wraps in `Retry(max_retries=1)` |
| `websec_test/engine/__init__.py` | Modified — exports `CheckAdapter`, `CheckTreeBuilder` |
| `websec_test/results/models.py` | Modified — added `TestStatus.INFO` (needed by CheckAdapter's PASS/INFO success check) |
| `tests/test_bt_adapters.py` | Modified — appended 6 CheckAdapter tests |
| `tests/test_bt_builder.py` | Created — 4 CheckTreeBuilder tests |

## Test results
```
209 passed in 16.80s
```

All tests in `tests/` pass (ignoring integration tests). Full suite: BT nodes, decorators, adapters, builder, plus all scanner/auth/module tests.

## Key design decisions
- `CheckAdapter.__init__(name, check_fn, endpoint)` — endpoint is passed explicitly rather than read from blackboard, keeping the adapter stateless per-check
- `CheckAdapter.do_tick` — SUCCESS if `TestStatus in (PASS, INFO)`, FAILURE otherwise; relies on `Action.tick` exception handler for unexpected errors
- `CheckTreeBuilder.build` — `@staticmethod` since it uses no instance state
- Endpoint path resolution — tries `url` attr, falls back to `path` attr, then `str(ep)`
- `TestStatus.INFO` was missing from the enum — added it since it's referenced in the adapter's success condition

## Concerns
None. Interface matches the brief, all tests green.
