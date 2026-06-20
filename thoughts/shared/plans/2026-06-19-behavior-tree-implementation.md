# Implementation Plan: Behavior Tree Engine

**Date:** 2026-06-19
**Design Spec:** `docs/superpowers/specs/2026-06-19-behavior-tree-design.md`

## Overview

Build a lightweight Behavior Tree engine in `websec_test/engine/` (5 source files) with 5 test files. ~400 lines of engine code, ~30 new tests. All existing 151 tests must continue passing.

---

## Layer 0: Engine Core (no dependencies)

### Task 0.1 — `websec_test/engine/__init__.py`

- Export all public API: `NodeStatus`, `Blackboard`, `Node`, `Sequence`, `Selector`, `Parallel`, `Action`, `Condition`, `Retry`, `Timeout`, `Invert`, `Cooldown`, `Log`, `ModuleAdapter`
- Imports from sibling modules

**Dependencies:** None (but needs nodes.py, leaves.py, decorators.py, adapters.py to exist first — can be stubbed then filled)
**Verify:** `python -c "from websec_test.engine import *; print('ok')"`

---

### Task 0.2 — `websec_test/engine/nodes.py`

Implement:
- `NodeStatus(Enum)` — SUCCESS, FAILURE, RUNNING
- `Blackboard` dataclass — `client`, `target`, `results: list`, `_store: dict`; methods `add_result()`, `get()`, `set()`
- `Node(ABC)` — `__init__(self, name)`, abstract `tick(blackboard) -> NodeStatus`
- `Sequence` — children list, ticks left-to-right, short-circuits on FAILURE
- `Selector` — children list, ticks left-to-right, short-circuits on SUCCESS
- `Parallel` — children list + `min_success`, ticks all (sequentially for P1), returns SUCCESS if >= min_success succeed

**Verify:** `python -c "from websec_test.engine.nodes import *; print('ok')"`

---

## Layer 1: Leaves & Decorators (depends on nodes.py)

### Task 1.1 — `websec_test/engine/leaves.py`

Implement:
- `Action(Node)` — abstract with `do_tick(blackboard)`; `tick()` calls `do_tick()`, catches exceptions → FAILURE
- `Condition(Node)` — takes a predicate function `(Blackboard) -> bool`; `tick()` evaluates predicate, returns SUCCESS/FAILURE

**Dependencies:** `nodes.py` (Node, NodeStatus, Blackboard)
**Verify:** `python -c "from websec_test.engine.leaves import *; print('ok')"`

---

### Task 1.2 — `websec_test/engine/decorators.py`

Implement:
- `Decorator(Node)` — wraps `child: Node`; base class for all decorators
- `Retry(Decorator)` — `max_attempts: int`, `delay: float`; re-ticks child on FAILURE up to N times with `time.sleep(delay)` between attempts
- `Timeout(Decorator)` — `max_seconds: float`; uses `signal.SIGALRM` on Unix / `threading.Timer` on Windows to enforce deadline; returns FAILURE on timeout
- `Invert(Decorator)` — flips child's SUCCESS ↔ FAILURE
- `Cooldown(Decorator)` — `min_interval: float`; tracks last tick time, skips child (returns SUCCESS) if ticked within interval
- `Log(Decorator)` — `label: str`; prints entry/exit + elapsed time; passes child status through unchanged

**Dependencies:** `nodes.py` (Node, NodeStatus, Blackboard)
**Verify:** `python -c "from websec_test.engine.decorators import *; print('ok')"`

---

## Layer 2: Adapters (depends on nodes.py and leaves.py)

### Task 2.1 — `websec_test/engine/adapters.py`

Implement:
- `ModuleAdapter(Action)` — wraps any existing module class
  - `__init__(self, name, module)` — stores module reference
  - `do_tick(blackboard)`:
    1. Call `module.discover(client, target)` → endpoints
    2. Call `module.test(client, target, endpoints)` → TestResult list
    3. `blackboard.add_result(r)` for each result
    4. Return FAILURE if any result has status FAIL or ERROR, else SUCCESS
    5. On exception: create ERROR TestResult, add to blackboard, return FAILURE

**Dependencies:** `nodes.py`, `leaves.py`; imports `TestResult`, `TestStatus`, `Severity` from `websec_test.results.models`
**Verify:** `python -c "from websec_test.engine.adapters import *; print('ok')"`

---

## Layer 3: Tests (depends on all engine code)

### Task 3.1 — `tests/test_bt_nodes.py`

Test cases (~12 tests):
- `test_sequence_all_success` — 3 child Actions returning SUCCESS → Sequence returns SUCCESS
- `test_sequence_short_circuit` — 2nd child returns FAILURE → 3rd never ticks
- `test_selector_first_success` — 1st child returns SUCCESS → 2nd never ticks
- `test_selector_all_fail` — all children FAILURE → Selector returns FAILURE
- `test_parallel_meets_threshold` — 3/4 children SUCCESS, min_success=3 → Parallel SUCCESS
- `test_parallel_fails_threshold` — 2/4 children SUCCESS, min_success=3 → Parallel FAILURE
- `test_node_status_enum` — SUCCESS, FAILURE, RUNNING have correct string values
- `test_node_abstract` — cannot instantiate Node directly
- `test_blackboard_add_result` — results appended correctly
- `test_blackboard_get_set` — key/value isolation works
- `test_blackboard_default` — get returns default for missing key
- `test_sequence_no_children` — empty Sequence returns SUCCESS

**Dependencies:** All engine source files
**Verify:** `pytest tests/test_bt_nodes.py -v`

---

### Task 3.2 — `tests/test_bt_decorators.py`

Test cases (~8 tests):
- `test_retry_succeeds_after_retry` — child fails twice then succeeds → Retry returns SUCCESS
- `test_retry_exhausted` — child always fails → Retry returns FAILURE after max_attempts
- `test_timeout_exceeds` — child that takes too long → Timeout returns FAILURE
- `test_timeout_within_limit` — fast child → Timeout returns child's status
- `test_invert_flips` — child FAILURE → Invert returns SUCCESS and vice versa
- `test_cooldown_skips` — second tick within interval → skipped (returns SUCCESS)
- `test_cooldown_allows` — tick after interval → runs normally
- `test_log_pass_through` — Log returns child's status unchanged

**Dependencies:** All engine source files
**Verify:** `pytest tests/test_bt_decorators.py -v`

---

### Task 3.3 — `tests/test_bt_blackboard.py`

Test cases (~5 tests):
- `test_blackboard_initialization` — client, target set; results empty; _store empty
- `test_blackboard_add_result` — single + multiple results appended in order
- `test_blackboard_get_set` — basic read/write roundtrip
- `test_blackboard_get_default` — missing key returns default sentinel
- `test_blackboard_key_isolation` — setting key A doesn't affect key B

**Dependencies:** All engine source files
**Verify:** `pytest tests/test_bt_blackboard.py -v`

---

### Task 3.4 — `tests/test_bt_adapters.py`

Test cases (~5 tests):
- `test_module_adapter_success` — module returns all PASS → ModuleAdapter returns SUCCESS, results in blackboard
- `test_module_adapter_failure` — module returns some FAIL/ERROR → returns FAILURE
- `test_module_adapter_exception` — module raises → ERROR TestResult added, returns FAILURE
- `test_module_adapter_discover_test_called` — verify discover() and test() are called with correct args
- `test_module_adapter_real_module` — wrap HeadersModule, mock HTTP with `responses`, verify output

**Dependencies:** All engine source files; uses `responses` library
**Verify:** `pytest tests/test_bt_adapters.py -v`

---

### Task 3.5 — `tests/test_bt_integration.py`

Test cases (~3 tests):
- `test_full_tree_execution` — build tree from ALL_MODULES, run with mocked HTTP responses, verify all results collected
- `test_custom_tree` — custom tree with Sequence → Selector → Retry → ModuleAdapter, verify execution order
- `test_regression_existing_tests` — assert all 151 existing tests still pass (can be a meta-test or manual verification step)

**Dependencies:** All engine source files; imports `create_module` from `websec_test.main`
**Verify:** `pytest tests/test_bt_integration.py -v`

---

## Execution Order (Dependency Graph)

```
Layer 0:  [nodes.py] ──→ [__init__.py stub]
              │
Layer 1:  [leaves.py]   [decorators.py]
              │                │
Layer 2:  [adapters.py] ←─────┘
              │
Layer 3:  [test_bt_nodes.py, test_bt_decorators.py, 
           test_bt_blackboard.py, test_bt_adapters.py,
           test_bt_integration.py]

Then: finalize __init__.py with all exports
Then: verify `pytest tests/ -v` passes (151 existing + ~30 new)
```

## Files Summary

| # | File | Type | Est. Lines | Depends On |
|---|------|------|-----------|------------|
| 1 | `websec_test/engine/__init__.py` | source | 15 | all engine files |
| 2 | `websec_test/engine/nodes.py` | source | 100 | — |
| 3 | `websec_test/engine/leaves.py` | source | 40 | nodes.py |
| 4 | `websec_test/engine/decorators.py` | source | 100 | nodes.py |
| 5 | `websec_test/engine/adapters.py` | source | 45 | nodes.py, leaves.py |
| 6 | `tests/test_bt_nodes.py` | test | 90 | all engine |
| 7 | `tests/test_bt_decorators.py` | test | 70 | all engine |
| 8 | `tests/test_bt_blackboard.py` | test | 40 | all engine |
| 9 | `tests/test_bt_adapters.py` | test | 70 | all engine |
| 10 | `tests/test_bt_integration.py` | test | 50 | all engine, main.py |

**Total:** ~620 lines (400 source + 320 test)
