# Behavior Tree Engine Completion & DevSecOps CI/CD Design

**Date:** 2026-06-30
**Status:** Draft
**Approach:** B — Core+Check

## Overview

The WebSec Test project has a working Sequence+Action behavior tree and a broken CI workflow.
This design completes the BT engine with missing node types, adds check-level granularity with
Selectors for fallback, reorganizes modules into classified subfolders, and makes the
DevSecOps pipeline actually functional.

---

## Part 1: Behavior Tree Engine

### 1.1 Node Types

#### Selector (nodes.py)

OR node. Ticks children in order, returns SUCCESS on first success (short-circuits).
Returns FAILURE if all children fail.

```python
class Selector(Node):
    def __init__(self, name, children=None):
        super().__init__(name)
        self.children = children or []
    def tick(self, blackboard):
        for child in self.children:
            status = child.tick(blackboard)
            if status == NodeStatus.SUCCESS:
                return NodeStatus.SUCCESS
            if status == NodeStatus.RUNNING:
                return NodeStatus.RUNNING
        return NodeStatus.FAILURE
```

#### Condition (leaves.py)

Predicate leaf node. Takes a callable `fn(blackboard) -> bool`. Returns SUCCESS if
callable returns True, FAILURE otherwise. Used for branching in Selector trees.

```python
class Condition(Action):
    def __init__(self, name, fn):
        super().__init__(name)
        self.fn = fn
    def do_tick(self, blackboard):
        return NodeStatus.SUCCESS if self.fn(blackboard) else NodeStatus.FAILURE
```

#### Parallel (nodes.py)

Runs all children regardless of individual outcomes. Returns SUCCESS if at least N
children succeed (N defaults to 1, configurable via `min_success`). Execution is
sequential (no threading).

```python
class Parallel(Node):
    def __init__(self, name, children=None, min_success=1):
        super().__init__(name)
        self.children = children or []
        self.min_success = min_success
    def tick(self, blackboard):
        successes = 0
        for child in self.children:
            status = child.tick(blackboard)
            if status == NodeStatus.SUCCESS:
                successes += 1
        return NodeStatus.SUCCESS if successes >= self.min_success else NodeStatus.FAILURE
```

### 1.2 Decorators (decorators.py)

New file. Each decorator wraps a single child node.

#### Retry

On FAILURE, retry up to N times with optional delay. Returns child's final status.

```python
class Retry(Decorator):
    def __init__(self, name, child, max_retries=1, delay=0):
        super().__init__(name, child)
        self.max_retries = max_retries
        self.delay = delay
    def do_tick(self, blackboard):
        for attempt in range(self.max_retries + 1):
            status = self.child.tick(blackboard)
            if status == NodeStatus.SUCCESS:
                return NodeStatus.SUCCESS
            if self.delay > 0:
                time.sleep(self.delay)
        return NodeStatus.FAILURE
```

#### Timeout

Fail if child takes longer than T seconds. Uses threading.Timer on all platforms.

```python
class Timeout(Decorator):
    def __init__(self, name, child, timeout=30):
        super().__init__(name, child)
        self.timeout = timeout
    def do_tick(self, blackboard):
        result = [NodeStatus.FAILURE]
        def done():
            # raises via timeout flag
            pass
        timer = threading.Timer(self.timeout, lambda: result.append(NodeStatus.FAILURE))
        timer.start()
        try:
            status = self.child.tick(blackboard)
            result[0] = status
        finally:
            timer.cancel()
        return result[0]
```

#### Invert

Flips child result: SUCCESS ↔ FAILURE.

```python
class Invert(Decorator):
    def do_tick(self, blackboard):
        status = self.child.tick(blackboard)
        if status == NodeStatus.SUCCESS:
            return NodeStatus.FAILURE
        if status == NodeStatus.FAILURE:
            return NodeStatus.SUCCESS
        return status  # RUNNING unchanged
```

### 1.3 Decorator Base Class (decorators.py)

```python
class Decorator(Node):
    def __init__(self, name, child):
        super().__init__(name)
        self.child = child
```

### 1.4 Exported API (engine/__init__.py)

```python
from .nodes import NodeStatus, Blackboard, Node, Sequence, Selector, Parallel
from .leaves import Action, Condition
from .adapters import ModuleAdapter, CheckAdapter, CheckTreeBuilder
from .decorators import Decorator, Retry, Timeout, Invert
```

---

## Part 2: Check-Level Behavior Tree

### 2.1 Convention

Every module class defines test methods named `check_<name>`. Each method receives
`(client, target, endpoint)` and returns a `TestResult`.

```python
# websec_test/modules/authentication/headers.py
class HeadersModule:
    def check_strict_transport_security(self, client, target, endpoint):
        ...
        return TestResult(...)

    def check_csp(self, client, target, endpoint):
        ...
        return TestResult(...)
```

Modules may optionally define a `SELECTOR_GROUPS` dict to group checks under
Selector nodes (fallback chains):

```python
SELECTOR_GROUPS = {
    "sqli_techniques": ["check_sqli_error_based", "check_sqli_time_based",
                        "check_sqli_blind"],
}
```

Checks within a selector group are wrapped in a Selector node — if one passes, the
group passes. Checks not in any group are direct children of the endpoint Sequence.

### 2.2 CheckAdapter (adapters.py)

Leaf node wrapping a single check method.

```python
class CheckAdapter(Action):
    def __init__(self, name, check_fn, endpoint):
        super().__init__(name)
        self.check_fn = check_fn
        self.endpoint = endpoint
    def do_tick(self, blackboard):
        result = self.check_fn(blackboard.client, blackboard.target, self.endpoint)
        blackboard.add_result(result)
        return NodeStatus.SUCCESS if result.status in (TestStatus.PASS, TestStatus.INFO) \
               else NodeStatus.FAILURE
```

### 2.3 CheckTreeBuilder (builder.py)

Takes a module instance + discovered endpoints. Builds a tree:

```
Sequence(module_name)
  Sequence(endpoint_1)
    Retry(CheckAdapter(check_1))
    Selector(sqli_group)
      Retry(CheckAdapter(check_sqli_error))
      Retry(CheckAdapter(check_sqli_time))
    Retry(CheckAdapter(check_n))
  Sequence(endpoint_2)
    ...
```

```python
class CheckTreeBuilder:
    @staticmethod
    def build(module_instance, module_name, endpoints):
        children = []
        selector_groups = getattr(module_instance, 'SELECTOR_GROUPS', {})
        check_methods = [(name, fn) for name, fn in
                         inspect.getmembers(module_instance, inspect.ismethod)
                         if name.startswith('check_')]
        check_names = {name for name, _ in check_methods}
        used = set()
        for endpoint in endpoints:
            endpoint_children = []
            for group_name, check_names_in_group in selector_groups.items():
                group_children = []
                for cn in check_names_in_group:
                    fn = getattr(module_instance, cn, None)
                    if fn:
                        group_children.append(
                            Retry(f"{cn}", CheckAdapter(cn, fn, endpoint), 1))
                        used.add(cn)
                if group_children:
                    endpoint_children.append(Selector(group_name, group_children))
            for name, fn in check_methods:
                if name not in used:
                    endpoint_children.append(
                        Retry(name, CheckAdapter(name, fn, endpoint), 1))
            children.append(Sequence(str(endpoint.url or endpoint.path), endpoint_children))
        return Sequence(module_name, children)
```

### 2.4 Integration into main.py

The `run()` function changes tree construction:

```python
# Current: wraps whole module in ModuleAdapter
# New: uses CheckTreeBuilder for check-level granularity
for modname in sorted(module_names):
    mod = module_factories[modname](cfg)
    endpoints = mod.discover(client, target)
    tree = CheckTreeBuilder.build(mod, modname, endpoints, client, target)
    full_sequence.children.append(tree)
```

The `--check` mode filters results by test_name as before, but now the tree
has per-check nodes.

### 2.5 Backward Compatibility

The old `ModuleAdapter` path remains for modules that haven't been migrated to
check-level. `ModuleAdapter.do_tick` checks if the module has `check_*` methods
and delegates to `CheckTreeBuilder.build()` automatically.

---

## Part 3: Module Folder Reorganization

### 3.1 New Layout

```
websec_test/modules/
├── __init__.py                    # empty
├── _shared.py                     # Endpoint, parse_form_inputs (unchanged)
├── authentication/
│   ├── __init__.py                # re-exports for backward compat
│   ├── auth.py
│   ├── authz.py
│   └── csrf.py
├── injection/
│   ├── __init__.py                # re-exports for backward compat
│   ├── sqli.py
│   ├── xss.py
│   ├── nosql.py
│   ├── cmd_injection.py
│   └── injection.py               # legacy combined module
└── configuration/
    ├── __init__.py                # re-exports for backward compat
    ├── headers.py
    ├── cookies.py
    ├── ssl_tls.py
    ├── cors.py
    ├── disclosure.py
    └── methods.py
```

### 3.2 Loader Changes

The `loader.py` uses `pkgutil.walk_packages()` instead of `iter_modules()` to
scan subpackages recursively. Module names include the subpackage prefix
(e.g. `authentication.auth`, `injection.sqli`).

### 3.3 Backward Compatibility

Each subfolder `__init__.py` imports module classes from their files so
`from websec_test.modules import HeadersModule` still works. The CLI accepts
both `--modules headers` (short name) and `--modules authentication.headers`
(qualified name).

---

## Part 4: Module Check Migration

Each module gets its checks split into individual `check_*` methods with
Selector groups where applicable.

### 4.1 headers.py → configuration/headers.py

8 checks → 8 check methods. No Selector groups (each check is independent).

### 4.2 sqli.py → injection/sqli.py

15 checks (multi-engine). Selector group `sqli_techniques` maps to error-based,
time-based, blind approaches.

### 4.3 auth.py → authentication/auth.py

4 checks (blank password, SQLi bypass, rate limiting, user enumeration).
Selector group `auth_bypass` contains the SQLi bypass methods.

### 4.4 Other modules

Similar treatment. Each `check_*` method is self-contained and returns one
`TestResult`.

---

## Part 5: DevSecOps CI/CD Fix

### 5.1 Problem

`.github/workflows/security-scan.yml` references:
- `scripts/security_scanner.py` → does not exist
- `scripts/vulnerability_assessor.py` → does not exist
- `scripts/compliance_checker.py` → does not exist

Actual code lives in `websec_test/security/`.

### 5.2 Fix: Wrapper Scripts

Create `scripts/` directory with thin CLI wrappers that call the corresponding
`websec_test.security` modules:

```
scripts/
├── security_scanner.py         # CLI: calls websec_test.security.scanner.SecurityScanner
├── vulnerability_assessor.py   # CLI: calls websec_test.security.assessor
└── compliance_checker.py       # CLI: calls websec_test.security.checker
```

Each wrapper is minimal (~10 lines):

```python
#!/usr/bin/env python3
"""Thin wrapper: delegates to websec_test.security.scanner."""
import sys
from websec_test.security.scanner import SecurityScanner
if __name__ == "__main__":
    scanner = SecurityScanner()
    results = scanner.scan(sys.argv[1] if len(sys.argv) > 1 else ".")
    sys.exit(scanner.exit_code(results))
```

### 5.3 Fix: Workflow Corrections

- Add `pip install -e ".[dev]"` (editable install so `websec_test` is importable)
- Fix `requirements.txt` → `pyproject.toml` reference
- Add `--json --output` flags to the wrapper scripts for the nightly audit path
- Set `fail-fast: false` on the matrix

### 5.4 Additional: Dockerfile

Minimal Dockerfile for running scans in CI:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -e ".[dev]"
ENTRYPOINT ["python", "-m", "websec_test.main"]
```

---

## Part 6: Testing

### 6.1 Unit Tests

| File | Tests |
|---|---|
| `tests/test_bt_nodes.py` | Selector, Parallel (create, tick, short-circuit) |
| `tests/test_bt_decorators.py` | Retry, Timeout, Invert |
| `tests/test_bt_adapters.py` | CheckAdapter, CheckTreeBuilder |
| `tests/test_loader.py` | Subpackage discovery |

### 6.2 Module-Level Tests

Existing test files per module (`test_headers.py`, `test_auth.py`, etc.) updated:
- Test that `check_*` methods return `TestResult`
- Test that `discover()` still works
- Test that `CheckTreeBuilder.build()` creates correct tree structure

---

## Part 7: Non-Goals (Explicitly Out of Scope)

- True parallel execution with threads. Parallel node is sequential.
- `@register` decorator and `registry.py`. Check discovery is convention-based.
- Cooldown and Log decorators are omitted.
- Web UI for BT visualization.
- GitLab/Jenkins CI configs. Only GitHub Actions.

---

## Part 8: Implementation Order

1. Add `Selector`, `Parallel`, `Condition` classes to engine
2. Create `decorators.py` with `Decorator`, `Retry`, `Timeout`, `Invert`
3. Add `CheckAdapter`, `CheckTreeBuilder` to adapters.py
4. Create `builder.py` with `CheckTreeBuilder.build()`
5. Update `engine/__init__.py` exports
6. Reorganize modules into subfolders with `__init__.py` re-exports
7. Update `loader.py` for recursive subpackage scanning
8. Migrate each module: split `test()` into `check_*` methods, add `SELECTOR_GROUPS`
9. Update `main.py` to use `CheckTreeBuilder` instead of `ModuleAdapter`
10. Create `scripts/` wrapper scripts
11. Fix `security-scan.yml` paths
12. Add Dockerfile
13. Update tests for new node types and check-level architecture
14. Update docx if needed (future PR)

---

## Part 9: Pen-Testing Skill Alignment

The `security-pen-testing` skill references CLI tools and report formats that
this project should expose as the implementation backend. Four gaps to close:

### 9.1 Aligned Script Names

Pen-testing skill expects these entry points:

| Pen-testing Skill Reference | Spec Plan Name | Fix: Alias / Wrapper |
|---|---|---|
| `scripts/vulnerability_scanner.py` | `scripts/vulnerability_assessor.py` | Rename to `vulnerability_scanner.py` (or create as thin re-export of assessor) |
| `scripts/dependency_auditor.py` | Not planned | Create: delegates to `websec_test.security.assessor` dependency scan |
| `scripts/pentest_report_generator.py` | Not planned | Create: reads TestResult JSON, emits CVSS-enriched pen-test report |

All three scripts use `argparse` with `--target`, `--scope` (quick/full),
`--json`, `--output` flags matching the pen-testing skill's examples:

```bash
python scripts/vulnerability_scanner.py --target https://example.com --scope full
python scripts/dependency_auditor.py --file package.json --severity high
python scripts/pentest_report_generator.py --findings findings.json --format md --output report.md
```

### 9.2 CLI Flag Mapping

Pen-testing skill uses `--target web --scope full` vocabulary. The project's
`--target http://url --modules all` is functionally equivalent but incompatible.
Add a lightweight `--scope` flag as alias:

| Pen-testing Usage | WebSec Test Equivalent |
|---|---|
| `--target web` | `--target <url>` (accept plain `web` or URL) |
| `--scope full` | `--modules all` |
| `--scope quick` | `--modules headers,cookies,ssl_tls` |
| `--api` | `--modules csrf,cors,auth` |

Implementation: `parse_args()` normalizes `--target web` to `--target`
placeholder for discover-mode, and maps `--scope quick` to a curated
module subset. Keeps backward compat with existing `--modules` flag.

### 9.3 Reference Documents

Pen-testing skill references three markdown files that don't exist in the repo:

- `references/owasp_top_10_checklist.md` — detailed test procedures per OWASP
  category, CVSS scoring guidance
- `references/attack_patterns.md` — payload libraries (JWT manipulation, SQLi
  per engine, SSRF bypass, XSS filter evasion)
- `references/responsible_disclosure.md` — disclosure timelines, communication
  templates, CVE request process

These were documented in design spec `2026-06-20-reference-docs-design.md`
(commit `648ec16`) but the implementation plan `2026-06-20-reference-docs-implementation.md`
was never executed. Create from the existing design spec.

### 9.4 CVSS-Enriched Report Format

Pen-testing expects findings with `cvss_score`, `cvss_vector`, `impact` fields.
Current `TestResult` model has `severity` (enum: LOW/MEDIUM/HIGH/CRITICAL) and
`evidence` but no CVSS data.

Add optional `cvss_score` and `cvss_vector` fields to `TestResult` model:

```python
@dataclass
class TestResult:
    ...
    cvss_score: float | None = None
    cvss_vector: str | None = None
```

The `Reporter.to_json()` includes these fields when present.
`pentest_report_generator.py` reads the JSON output and maps severity→CVSS
score range for missing values (LOW→0.1-3.9, MEDIUM→4.0-6.9, HIGH→7.0-8.9,
CRITICAL→9.0-10.0).

### 9.5 Implementation Order (Pen-Testing Alignment)

15. Create `scripts/vulnerability_scanner.py` (wrapper naming alignment)
16. Create `scripts/dependency_auditor.py`
17. Create `scripts/pentest_report_generator.py`
18. Add `cvss_score`, `cvss_vector` fields to `TestResult` model
19. Add `--scope` flag to CLI (thin alias for --modules subsets)
20. Create reference docs: `references/owasp_top_10_checklist.md`,
    `references/attack_patterns.md`, `references/responsible_disclosure.md`
