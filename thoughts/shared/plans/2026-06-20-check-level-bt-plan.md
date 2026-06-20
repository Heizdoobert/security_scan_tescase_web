---
date: 2026-06-20
topic: "WebSec Test — Check-Level Behavior Trees Implementation Plan"
status: draft
parent_spec: "docs/superpowers/specs/2026-06-20-check-level-bt-design.md"
test_baseline: 184
test_target: ~209
---

## Overview

Decompose module-level BT nodes into per-check nodes. Introduce `CheckAdapter`, `DiscoverAction`, `CheckSpec`, `CheckTreeBuilder`, and a registry. Migrate 3 modules (headers, auth, cors) as reference implementations.

**Constraints:**
- All 184 existing tests must still pass — additive changes only
- `ModuleAdapter` continues to work unchanged
- Default `build_tree()` still uses `ModuleAdapter` — check-level is opt-in
- No new Python dependencies
- Check functions are simple `(client, target, blackboard) -> TestResult` callables

---

## Phase A — Engine Core (no module deps)

Tasks A1–A3 are independent of each other and can run in parallel.

### A1 — CheckSpec dataclass + registry

- **Files to create/modify:**
  - CREATE `websec_test/engine/registry.py`
  - CREATE `websec_test/engine/builder.py` (CheckSpec only; CheckTreeBuilder in A3)
- **What to change:**
  - In `registry.py`: define `check_registry: dict[str, Callable[[], list[CheckSpec]]]` + `register(module_name)` decorator
  - In `builder.py`: define `@dataclass CheckSpec` with fields: `name: str`, `fn: Callable`, `severity: Severity`, `depends_on: list[str] | None = None`, `module_name: str = ""`
  - Both importable from `websec_test.engine`
- **Dependencies:** None
- **How to verify:** `pytest tests/ -k "test_check_spec"` — will create test in C2

### A2 — CheckAdapter + DiscoverAction (in adapters.py)

- **Files to modify:**
  - MODIFY `websec_test/engine/adapters.py`
- **What to change:**
  - Add `CheckAdapter(Action)` — wraps `check_fn(client, target, blackboard) -> TestResult`, calls `blackboard.add_result()`, returns `FAILURE` if result status is FAIL/ERROR else `SUCCESS`. If `check_fn` returns None, return `SUCCESS` (skip/no-op). Exception handing via inherited `Action.do_tick` → `NodeStatus.FAILURE` + add ERROR `TestResult`.
  - Add `DiscoverAction(Action)` — wraps `discover_fn(client, target) -> list[Endpoint]`, stores endpoints on blackboard as `{name}_endpoints`, returns `SUCCESS` if endpoints found else `FAILURE`
  - `CheckAdapter.__init__(self, name, check_fn, module_name="")`
  - `DiscoverAction.__init__(self, name, discover_fn)`
  - Keep `ModuleAdapter` class entirely unchanged
- **Dependencies:** None (uses `Action` from leaves.py and `TestResult`/`TestStatus` from models.py — both exist)
- **How to verify:** `pytest tests/test_bt_check_adapter.py` (see C1)

### A3 — CheckTreeBuilder (in builder.py)

- **Files to create/modify:**
  - MODIFY `websec_test/engine/builder.py` (add CheckTreeBuilder alongside CheckSpec from A1)
- **What to change:**
  - Add `CheckTreeBuilder` class with:
    - `build_module(module_name, discover_fn, checks: list[CheckSpec]) -> Sequence` — builds a tree with `DiscoverAction` + `Parallel` of `CheckAdapter` nodes
    - `_group_by_dependency(specs, nodes) -> list[list[Node]]` — topological sort: no-deps checks go in group 0, checks depending on group-0 go in group 1, etc. If only one group, use a single `Parallel(..., min_success=0)`. If multiple groups, wrap in `Sequence` of `Parallel` groups.
  - Store cached `(endpoint, response)` pairs on blackboard from `DiscoverAction` so check functions can read them instead of re-requesting
- **Dependencies:** A1 (CheckSpec), A2 (CheckAdapter, DiscoverAction)
- **How to verify:** `pytest tests/test_bt_builder.py` (see C2)

---

## Phase B — Module Migration

B1–B3 are independent of each other (each module is standalone) but all depend on Phase A being done.

### B1 — Headers module check functions

- **Files to modify:**
  - MODIFY `websec_test/modules/headers.py`
- **What to change:**
  - Extract a standalone `_check_header(client, target, blackboard, header_name, info)` function that reads endpoints from blackboard, makes HTTP request, returns `TestResult`
  - Add factory `headers_check_specs()` decorated with `@register("headers")` — creates 8 `CheckSpec` instances (one per `HEADER_CHECKS` entry), all with `depends_on=None` (independent)
  - Existing `HeadersModule.test()` and `HeadersModule.discover()` remain unchanged for ModuleAdapter backward compat
- **Dependencies:** Phase A (A1 registry, A2 CheckAdapter)
- **How to verify:** `pytest tests/test_bt_checks_headers.py` (see C3); also `pytest tests/test_headers.py` (existing, must still pass)

### B2 — Auth module check functions

- **Files to modify:**
  - MODIFY `websec_test/modules/auth.py`
- **What to change:**
  - Extract standalone check functions: `_check_blank_password`, `_check_sqli_bypass`, `_check_rate_limiting`, `_check_username_enumeration`
  - Each function: `(client, target, blackboard) -> TestResult`, reads discovered form action from blackboard
  - Add factory `auth_check_specs()` decorated with `@register("auth")`:
    - `blank_password_login` — depends_on=None
    - `sqli_login_bypass` — depends_on=["blank_password_login"]
    - `rate_limiting` — depends_on=["blank_password_login"]
    - `username_enumeration` — depends_on=["blank_password_login"]
  - Existing `AuthModule.test()` and `AuthModule.discover()` remain unchanged
- **Dependencies:** Phase A
- **How to verify:** `pytest tests/test_bt_checks_auth.py` (see C4); `pytest tests/test_auth.py` (existing, must still pass)

### B3 — CORS module check functions

- **Files to modify:**
  - MODIFY `websec_test/modules/cors.py`
- **What to change:**
  - Extract standalone check functions: `_check_wildcard_origin`, `_check_credentials_with_wildcard`, `_check_reflected_origin`
  - Each function: `(client, target, blackboard) -> TestResult`, reads endpoints from blackboard, sends request with spoofed Origin header
  - Add factory `cors_check_specs()` decorated with `@register("cors")` — 3 CheckSpecs, all independent
  - Existing `CorsModule.test()` and `CorsModule.discover()` remain unchanged
- **Dependencies:** Phase A
- **How to verify:** `pytest tests/test_bt_checks_cors.py` (see C5); `pytest tests/test_cors.py` (existing, must still pass)

---

## Phase C — Tests

C1–C5 are independent of each other. Each depends on its respective Phase A/B task.

### C1 — test_bt_check_adapter.py

- **Files to create:**
  - CREATE `tests/test_bt_check_adapter.py`
- **What to test (~7 tests):**
  - `test_check_adapter_success` — CheckAdapter calls check_fn, adds result to blackboard, returns SUCCESS on PASS
  - `test_check_adapter_failure` — returns FAILURE on FAIL status
  - `test_check_adapter_error` — returns FAILURE on ERROR status
  - `test_check_adapter_none_result` — check_fn returns None → SUCCESS (skip)
  - `test_check_adapter_exception` — check_fn raises → FAILURE + ERROR result added (inherited from Action.do_tick)
  - `test_discover_action_stores_endpoints` — DiscoverAction stores endpoints on blackboard
  - `test_discover_action_no_endpoints` — returns FAILURE when discover_fn returns empty
- **Depends on:** A2
- **How to verify:** `pytest tests/test_bt_check_adapter.py -v`

### C2 — test_bt_builder.py

- **Files to create:**
  - CREATE `tests/test_bt_builder.py`
- **What to test (~6 tests):**
  - `test_check_spec_creation` — CheckSpec stores fields correctly
  - `test_build_module_no_deps` — BuildModule with all-independent checks produces `Sequence(module_name) → [DiscoverAction, Parallel]`
  - `test_build_module_with_deps` — BuildModule with depends_on produces `Sequence → [DiscoverAction, Sequence → [group0_checks, Parallel(group1_checks)]]`
  - `test_dependency_grouping_independent` — _group_by_dependency returns single group for no-deps specs
  - `test_dependency_grouping_chain` — _group_by_dependency returns [group0], [group1] for chain deps
  - `test_register_decorator` — @register("foo") adds factory to check_registry
- **Depends on:** A3 (A1 + A2 transitively)
- **How to verify:** `pytest tests/test_bt_builder.py -v`

### C3 — test_bt_checks_headers.py

- **Files to create:**
  - CREATE `tests/test_bt_checks_headers.py`
- **What to test (~5 tests):**
  - `test_headers_check_tree_all_pass` — All 8 headers present → all CheckAdapters return SUCCESS
  - `test_headers_check_tree_one_fail` — One header missing → that CheckAdapter returns FAILURE, others SUCCESS
  - `test_headers_check_tree_one_error` — Request fails → all 8 return TestStatus.ERROR
  - `test_headers_discovery_failure` — Discovery returns empty → DiscoverAction returns FAILURE
  - `test_headers_specs_registered` — `check_registry["headers"]` exists and returns 8 CheckSpecs
- **Depends on:** B1
- **How to verify:** `pytest tests/test_bt_checks_headers.py -v`

### C4 — test_bt_checks_auth.py

- **Files to create:**
  - CREATE `tests/test_bt_checks_auth.py`
- **What to test (~5 tests):**
  - `test_auth_form_found_all_checks` — Form discovered → all 4 checks run
  - `test_auth_no_form_discovery_fails` — No login forms → DiscoverAction returns FAILURE
  - `test_auth_check_ordering_deps` — blank_password_login runs before sqli_login_bypass (ordering respects depends_on)
  - `test_auth_specs_registered` — `check_registry["auth"]` exists with 4 CheckSpecs
  - `test_auth_spec_dependencies` — sqli_login_bypass, rate_limiting, username_enumeration have `depends_on=["blank_password_login"]`
- **Depends on:** B2
- **How to verify:** `pytest tests/test_bt_checks_auth.py -v`

### C5 — test_bt_checks_cors.py

- **Files to create:**
  - CREATE `tests/test_bt_checks_cors.py`
- **What to test (~4 tests):**
  - `test_cors_all_pass` — No CORS issues → all 3 checks PASS
  - `test_cors_wildcard_fails` — ACAO: `*` → wildcard_origin FAIL, credentials_with_wildcard FAIL if ACAC:true
  - `test_cors_reflected_origin` — Server echoes Origin → reflected_origin FAIL
  - `test_cors_specs_registered` — `check_registry["cors"]` exists with 3 CheckSpecs
- **Depends on:** B3
- **How to verify:** `pytest tests/test_bt_checks_cors.py -v`

---

## Phase D — Integration

### D1 — engine/__init__.py exports

- **Files to modify:**
  - MODIFY `websec_test/engine/__init__.py`
- **What to change:**
  - Add imports: `CheckAdapter`, `DiscoverAction` from `adapters`
  - Add imports: `CheckSpec`, `CheckTreeBuilder` from `builder`
  - Add imports: `check_registry`, `register` from `registry`
  - Update `__all__` to include: `"CheckAdapter"`, `"DiscoverAction"`, `"CheckSpec"`, `"CheckTreeBuilder"`, `"check_registry"`, `"register"`
- **Depends on:** A1, A2, A3
- **How to verify:** `import websec_test.engine; dir(websec_test.engine)` shows all new types

### D2 — main.py check-level flag

- **Files to modify:**
  - MODIFY `websec_test/main.py`
- **What to change:**
  - Add `--check-level` CLI flag in `parse_args()` (store_true)
  - In `run()`: after building `module_map`, if `args.check_level`:
    - Import `CheckTreeBuilder`, `check_registry` from `websec_test.engine`
    - For each module: if name in `check_registry`, call `CheckTreeBuilder.build_module(name, module.discover, check_registry[name]())`
    - Else fall back to `ModuleAdapter(name, mod)`
  - Default `check_level=False` — no change to existing behavior
- **Depends on:** B1, B2, B3, D1
- **How to verify:** `pytest tests/test_main.py` (existing, must still pass); manual: `python -m websec_test.main --target http://localhost:8080/ --all --check-level`

### D3 — Integration test for check-level trees

- **Files to modify:**
  - MODIFY `tests/test_bt_integration.py` (append new tests, don't touch existing)
- **What to test (~3 new tests):**
  - `test_check_level_tree_execution` — Build a check-level tree with headers, tick it, verify per-check results on blackboard
  - `test_check_level_fallback_to_module` — For unregistered module (e.g., injection), CheckTreeBuilder falls back to ModuleAdapter
  - `test_mixed_check_and_module_tree` — Sequence with mixed CheckAdapter and ModuleAdapter nodes
- **Depends on:** B1, C3, D1
- **How to verify:** `pytest tests/test_bt_integration.py -v`

---

## Phase E — Validation

### E1 — Run full test suite

- **Script:** `pytest tests/ -v`
- **Expected:** 209 tests pass (184 existing + ~25 new)
- **Dependencies:** All phases
- **Failures to watch for:**
  - Regression in existing module tests (headers.py, auth.py, cors.py) — ensure test() methods unchanged
  - Import errors from __init__.py changes
  - main.py still passes its CLI parser tests

### E2 — Manual smoke test

- **Command:** `python -m websec_test.main --target http://localhost:8080/ --modules headers auth cors --check-level`
- **Expected:** Runs with per-check results visible in output; same summary as `ModuleAdapter` path
- **Dependencies:** All phases

---

## Execution Order (Recommended)

```
Phase A (parallel: A1, A2)
  └─ A3 (depends on A1, A2)
     └─ Phase B (parallel: B1, B2, B3; each depends on A1, A2, A3)
        └─ Phase C (parallel: C1, C2, C3, C4, C5)
           └─ Phase D (parallel: D1, D2, D3)
              └─ Phase E (E1, E2)
```

Solo implementer pass: A1→A2→A3→B1→B2→B3→C1→C2→C3→C4→C5→D1→D2→D3→E1→E2

Each Phase C test task can be verified immediately after its corresponding Phase B module is done.
