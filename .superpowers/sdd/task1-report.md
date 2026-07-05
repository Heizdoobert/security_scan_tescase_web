# Task 1 Report: Core BT Nodes + Decorators + Tests

## Status: DONE

## Commits

- `b1a6453` - feat: add Selector, Parallel, Condition, Retry, Timeout, Invert nodes

## Files Changed

| File | Action |
|------|--------|
| `websec_test/engine/nodes.py` | Added `Selector`, `Parallel` classes |
| `websec_test/engine/leaves.py` | Added `Condition` class |
| `websec_test/engine/decorators.py` | Created with `Decorator`, `Retry`, `Timeout`, `Invert` |
| `websec_test/engine/__init__.py` | Updated exports |
| `tests/test_bt_nodes.py` | Created — tests for Selector, Parallel, Condition |
| `tests/test_bt_decorators.py` | Created — tests for Retry, Timeout, Invert |

## Test Results

- **200 passed** (173 existing + 27 new), 0 failed, 0 errors
- Existing tests unchanged — no regressions

## Implementation Details

- **Selector**: Short-circuits on first SUCCESS or RUNNING; returns FAILURE if all fail
- **Parallel**: Runs all children sequentially; returns SUCCESS if `>= min_success` children succeed
- **Condition**: Extends `Action`; `fn(blackboard)` returns SUCCESS if True, FAILURE if False
- **Decorator**: Base class — `tick()` delegates to child (satisfies `Node`'s abstract method)
- **Retry**: Extends `Decorator`, overrides `tick()`. Tries `max_retries + 1` times with optional delay
- **Timeout**: Uses daemon thread + `threading.Event` (not `threading.Timer`). Returns FAILURE on timeout
- **Invert**: Extends `Decorator`. Flips SUCCESS↔FAILURE; RUNNING passes through unchanged

## Concerns

None.
