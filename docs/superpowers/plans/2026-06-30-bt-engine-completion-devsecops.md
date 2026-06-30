# BT Engine Completion & DevSecOps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Behavior Tree engine (Selector, Parallel, Condition, Retry, Timeout, Invert decorators, check-level CheckAdapter/CheckTreeBuilder) and fix DevSecOps CI/CD pipeline.

**Architecture:** Core BT nodes live in `engine/nodes.py` and `engine/leaves.py`. Decorators in new `engine/decorators.py`. Check-level infrastructure in `engine/adapters.py` and new `engine/builder.py`. Modules reorganized into subfolders (`authentication/`, `injection/`, `configuration/`). DevSecOps: wrapper scripts in `scripts/` fix broken CI workflow paths.

**Tech Stack:** Python 3.10+, pytest, responses (for HTTP mocking)

## Global Constraints

- All existing 173+ tests must continue to pass after each task
- `websec_test/main.py --all` must run without errors against a live target
- Module discovery must work from subpackages (`websec_test.modules.authentication.*`)
- No new dependencies beyond stdlib + existing `requests`, `responses`
- `Parallel` node is sequential (no threads)
- Timeout decorator uses daemon thread + `threading.Event` (no timer thread leak)
- Check methods named `check_<name>` — convention-based, no `@register` decorator
- Subfolder `__init__.py` files re-export module classes for backward compatibility

---

### Task 1: Core BT Nodes + Decorators + Tests

**Files:**
- Modify: `websec_test/engine/nodes.py` — add Selector, Parallel classes
- Modify: `websec_test/engine/leaves.py` — add Condition class
- Create: `websec_test/engine/decorators.py` — Decorator, Retry, Timeout, Invert
- Modify: `websec_test/engine/__init__.py` — new exports
- Create: `tests/test_bt_nodes.py` — tests for Selector, Parallel, Condition
- Create: `tests/test_bt_decorators.py` — tests for Retry, Timeout, Invert

**Interfaces:**
- Consumes: `Node` (ABC), `Action` (ABC), `NodeStatus`, `Blackboard` from existing engine
- Produces: `Selector(name, children)`, `Parallel(name, children, min_success=1)`, `Condition(name, fn)`, `Decorator(name, child)`, `Retry(name, child, max_retries=1, delay=0)`, `Timeout(name, child, timeout=30)`, `Invert(name, child)`

- [ ] **Step 1: Write Selector, Parallel, Condition tests**

Create `tests/test_bt_nodes.py`:

```python
"""Tests for Selector, Parallel, Condition nodes."""
import pytest
from websec_test.engine.nodes import NodeStatus, Blackboard, Sequence
from websec_test.engine.leaves import Action


class MockAction(Action):
    def __init__(self, name, status):
        super().__init__(name)
        self._status = status
        self.tick_count = 0
    def do_tick(self, blackboard):
        self.tick_count += 1
        return self._status


@pytest.fixture
def bb():
    return Blackboard(client="x", target="http://x")


# ── Selector ────────────────────────────────────────────────────────

def test_selector_success_on_first(bb):
    """Selector returns SUCCESS when first child succeeds (short-circuit)."""
    from websec_test.engine.nodes import Selector
    c1 = MockAction("c1", NodeStatus.SUCCESS)
    c2 = MockAction("c2", NodeStatus.SUCCESS)
    sel = Selector("sel", [c1, c2])
    assert sel.tick(bb) == NodeStatus.SUCCESS
    assert c1.tick_count == 1
    assert c2.tick_count == 0   # short-circuited


def test_selector_failure_all_fail(bb):
    from websec_test.engine.nodes import Selector
    c1 = MockAction("c1", NodeStatus.FAILURE)
    c2 = MockAction("c2", NodeStatus.FAILURE)
    sel = Selector("sel", [c1, c2])
    assert sel.tick(bb) == NodeStatus.FAILURE
    assert c1.tick_count == 1
    assert c2.tick_count == 1


def test_selector_fallback_on_failure(bb):
    from websec_test.engine.nodes import Selector
    c1 = MockAction("c1", NodeStatus.FAILURE)
    c2 = MockAction("c2", NodeStatus.SUCCESS)
    sel = Selector("sel", [c1, c2])
    assert sel.tick(bb) == NodeStatus.SUCCESS
    assert c1.tick_count == 1
    assert c2.tick_count == 1


def test_selector_empty_children(bb):
    from websec_test.engine.nodes import Selector
    sel = Selector("empty", [])
    assert sel.tick(bb) == NodeStatus.FAILURE


# ── Parallel ────────────────────────────────────────────────────────

def test_parallel_all_succeed(bb):
    from websec_test.engine.nodes import Parallel
    c1 = MockAction("c1", NodeStatus.SUCCESS)
    c2 = MockAction("c2", NodeStatus.SUCCESS)
    p = Parallel("p", [c1, c2])
    assert p.tick(bb) == NodeStatus.SUCCESS


def test_parallel_some_fail_below_threshold(bb):
    from websec_test.engine.nodes import Parallel
    c1 = MockAction("c1", NodeStatus.SUCCESS)
    c2 = MockAction("c2", NodeStatus.FAILURE)
    p = Parallel("p", [c1, c2], min_success=2)
    assert p.tick(bb) == NodeStatus.FAILURE


def test_parallel_some_fail_above_threshold(bb):
    from websec_test.engine.nodes import Parallel
    c1 = MockAction("c1", NodeStatus.SUCCESS)
    c2 = MockAction("c2", NodeStatus.FAILURE)
    p = Parallel("p", [c1, c2], min_success=1)
    assert p.tick(bb) == NodeStatus.SUCCESS


def test_parallel_default_min_success(bb):
    from websec_test.engine.nodes import Parallel
    c1 = MockAction("c1", NodeStatus.SUCCESS)
    c2 = MockAction("c2", NodeStatus.FAILURE)
    p = Parallel("p", [c1, c2])  # default min_success=1
    assert p.tick(bb) == NodeStatus.SUCCESS


# ── Condition ───────────────────────────────────────────────────────

def test_condition_true(bb):
    from websec_test.engine.leaves import Condition
    c = Condition("is_active", lambda bb: True)
    assert c.tick(bb) == NodeStatus.SUCCESS


def test_condition_false(bb):
    from websec_test.engine.leaves import Condition
    c = Condition("is_active", lambda bb: False)
    assert c.tick(bb) == NodeStatus.FAILURE


def test_condition_accesses_blackboard(bb):
    from websec_test.engine.leaves import Condition
    bb.set("status", "ok")
    c = Condition("check_status", lambda bb: bb.get("status") == "ok")
    assert c.tick(bb) == NodeStatus.SUCCESS
```

- [ ] **Step 2: Run Selector/Parallel/Condition tests — verify they fail**

```bash
python -m pytest tests/test_bt_nodes.py -v --tb=short
```
Expected: All fail with `ImportError` or `AttributeError` — classes don't exist yet.

- [ ] **Step 3: Add Selector and Parallel to nodes.py**

Append to `websec_test/engine/nodes.py` (after Sequence class):

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

- [ ] **Step 4: Add Condition to leaves.py**

Add to `websec_test/engine/leaves.py`:

```python
class Condition(Action):
    def __init__(self, name, fn):
        super().__init__(name)
        self.fn = fn
    def do_tick(self, blackboard):
        return NodeStatus.SUCCESS if self.fn(blackboard) else NodeStatus.FAILURE
```

- [ ] **Step 5: Run Selector/Parallel/Condition tests — verify they pass**

```bash
python -m pytest tests/test_bt_nodes.py -v --tb=short
```
Expected: 10 passed

- [ ] **Step 6: Write decorator tests**

Create `tests/test_bt_decorators.py`:

```python
"""Tests for Retry, Timeout, Invert decorators."""
import pytest
from websec_test.engine.nodes import NodeStatus, Blackboard
from websec_test.engine.decorators import Retry, Timeout, Invert
from websec_test.engine.leaves import Action


class MockAction(Action):
    def __init__(self, name, statuses):
        super().__init__(name)
        self.statuses = list(statuses)
        self.call_count = 0
    def do_tick(self, blackboard):
        status = self.statuses[self.call_count] if self.call_count < len(self.statuses) else NodeStatus.FAILURE
        self.call_count += 1
        return status


@pytest.fixture
def bb():
    return Blackboard(client="x", target="http://x")


# ── Retry ───────────────────────────────────────────────────────────

def test_retry_succeeds_first_try(bb):
    child = MockAction("c", [NodeStatus.SUCCESS])
    r = Retry("r", child, max_retries=2)
    assert r.tick(bb) == NodeStatus.SUCCESS
    assert child.call_count == 1


def test_retry_succeeds_on_retry(bb):
    child = MockAction("c", [NodeStatus.FAILURE, NodeStatus.SUCCESS])
    r = Retry("r", child, max_retries=2)
    assert r.tick(bb) == NodeStatus.SUCCESS
    assert child.call_count == 2


def test_retry_exhausted(bb):
    child = MockAction("c", [NodeStatus.FAILURE, NodeStatus.FAILURE, NodeStatus.FAILURE])
    r = Retry("r", child, max_retries=2)
    assert r.tick(bb) == NodeStatus.FAILURE
    assert child.call_count == 3  # initial + 2 retries


# ── Timeout ─────────────────────────────────────────────────────────

class SlowAction(Action):
    def __init__(self, name, delay):
        super().__init__(name)
        self.delay = delay
    def do_tick(self, blackboard):
        import time
        time.sleep(self.delay)
        return NodeStatus.SUCCESS


def test_timeout_does_not_trigger_on_fast_action(bb):
    child = SlowAction("slow", 0.001)
    t = Timeout("t", child, timeout=5)
    assert t.tick(bb) == NodeStatus.SUCCESS


def test_timeout_triggers(bb):
    child = SlowAction("slow", 10)
    t = Timeout("t", child, timeout=0.05)
    result = t.tick(bb)
    assert result == NodeStatus.FAILURE


# ── Invert ──────────────────────────────────────────────────────────

def test_invert_success_to_failure(bb):
    child = MockAction("c", [NodeStatus.SUCCESS])
    inv = Invert("inv", child)
    assert inv.tick(bb) == NodeStatus.FAILURE


def test_invert_failure_to_success(bb):
    child = MockAction("c", [NodeStatus.FAILURE])
    inv = Invert("inv", child)
    assert inv.tick(bb) == NodeStatus.SUCCESS
```

- [ ] **Step 7: Run decorator tests — verify they fail**

```bash
python -m pytest tests/test_bt_decorators.py -v --tb=short
```
Expected: All fail with `ModuleNotFoundError` — `decorators.py` doesn't exist yet.

- [ ] **Step 8: Create decorators.py**

Create `websec_test/engine/decorators.py`:

```python
"""Decorator nodes for Behavior Tree: Retry, Timeout, Invert."""
import time
import threading
from .nodes import Node, NodeStatus


class Decorator(Node):
    def __init__(self, name, child):
        super().__init__(name)
        self.child = child


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
            if self.delay > 0 and attempt < self.max_retries:
                time.sleep(self.delay)
        return status
    # Retry extends Action for do_tick pattern
    def tick(self, blackboard):
        try:
            return self.do_tick(blackboard)
        except Exception:
            return NodeStatus.FAILURE


class Timeout(Decorator):
    def __init__(self, name, child, timeout=30):
        super().__init__(name, child)
        self.timeout = timeout
    def do_tick(self, blackboard):
        result = [NodeStatus.FAILURE]
        done = threading.Event()
        def worker():
            try:
                status = self.child.tick(blackboard)
                result[0] = status
            finally:
                done.set()
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        done.wait(timeout=self.timeout)
        return result[0]


class Invert(Decorator):
    def tick(self, blackboard):
        status = self.child.tick(blackboard)
        if status == NodeStatus.SUCCESS:
            return NodeStatus.FAILURE
        if status == NodeStatus.FAILURE:
            return NodeStatus.SUCCESS
        return status
```

- [ ] **Step 9: Update engine/__init__.py exports**

Edit `websec_test/engine/__init__.py`:

```
Old:
from .nodes import NodeStatus, Blackboard, Node, Sequence
from .leaves import Action
from .adapters import ModuleAdapter

New:
from .nodes import NodeStatus, Blackboard, Node, Sequence, Selector, Parallel
from .leaves import Action, Condition
from .adapters import ModuleAdapter
from .decorators import Decorator, Retry, Timeout, Invert
```

- [ ] **Step 10: Run decorator tests — verify they pass**

```bash
python -m pytest tests/test_bt_decorators.py -v --tb=short
```

- [ ] **Step 11: Run ALL tests — verify nothing broken**

```bash
python -X utf8 -m pytest tests/ --tb=short -q --ignore=tests/test_integration.py --ignore=tests/test_integration_live.py
```
Expected: ~185 passed

- [ ] **Step 12: Commit**

```bash
git add websec_test/engine/nodes.py websec_test/engine/leaves.py websec_test/engine/decorators.py websec_test/engine/__init__.py tests/test_bt_nodes.py tests/test_bt_decorators.py
git commit -m "feat: add Selector, Parallel, Condition, Retry, Timeout, Invert nodes"
```

---

### Task 2: CheckAdapter + CheckTreeBuilder + Tests

**Files:**
- Create: `websec_test/engine/builder.py` — CheckTreeBuilder
- Modify: `websec_test/engine/adapters.py` — add CheckAdapter
- Modify: `websec_test/engine/__init__.py` — export CheckAdapter, CheckTreeBuilder
- Modify: `tests/test_bt_adapters.py` — add CheckAdapter tests
- Create: `tests/test_bt_builder.py` — CheckTreeBuilder tests

**Interfaces:**
- Consumes: `TestResult`, `TestStatus` from results.models; module objects with `check_*` methods; `Endpoint` from modules
- Produces: `CheckAdapter(name, check_fn, endpoint)` leaf; `CheckTreeBuilder.build(module_instance, module_name, endpoints) -> Sequence`

- [ ] **Step 1: Write CheckAdapter + CheckTreeBuilder tests**

Append to existing `tests/test_bt_adapters.py`:

```python
from websec_test.engine.adapters import CheckAdapter, CheckTreeBuilder
from websec_test.engine.nodes import Selector


class CheckMockModule:
    def __init__(self):
        self.discover_called = False
    def discover(self, client, target):
        self.discover_called = True
        return [type("EP", (), {"url": "/", "path": "/"})()]
    def check_pass(self, client, target, endpoint):
        return TestResult(module="mock", test_name="check_pass", status=TestStatus.PASS,
                          severity=Severity.LOW, endpoint="/", evidence="ok")
    def check_fail(self, client, target, endpoint):
        return TestResult(module="mock", test_name="check_fail", status=TestStatus.FAIL,
                          severity=Severity.HIGH, endpoint="/", evidence="broken")


# ── CheckAdapter ────────────────────────────────────────────────────

def test_check_adapter_pass(blackboard):
    module = CheckMockModule()
    adapter = CheckAdapter("check_pass", module.check_pass, type("EP", (), {"url": "/", "path": "/"})())
    result = adapter.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 1
    assert blackboard.results[0].test_name == "check_pass"


def test_check_adapter_fail(blackboard):
    module = CheckMockModule()
    adapter = CheckAdapter("check_fail", module.check_fail, type("EP", (), {"url": "/", "path": "/"})())
    result = adapter.tick(blackboard)
    assert result == NodeStatus.FAILURE


# ── CheckTreeBuilder ────────────────────────────────────────────────

def test_builder_creates_sequence_tree(blackboard):
    module = CheckMockModule()
    endpoints = [type("EP", (), {"url": "/", "path": "/"})()]
    tree = CheckTreeBuilder.build(module, "mock_module", endpoints)
    assert tree.name == "mock_module"
    assert len(tree.children) == 1  # one Sequence per endpoint


def test_builder_children_are_wrapped_in_retry(blackboard):
    module = CheckMockModule()
    endpoints = [type("EP", (), {"url": "/", "path": "/"})()]
    tree = CheckTreeBuilder.build(module, "mock_module", endpoints)
    endpoint_seq = tree.children[0]
    for child in endpoint_seq.children:
        from websec_test.engine.decorators import Retry
        assert isinstance(child, Retry)


def test_builder_supports_selector_groups(blackboard):
    module = CheckMockModule()
    module.SELECTOR_GROUPS = {"tech_group": ["check_pass"]}
    endpoints = [type("EP", (), {"url": "/", "path": "/"})()]
    tree = CheckTreeBuilder.build(module, "mock_module", endpoints)
    endpoint_seq = tree.children[0]
    # First child should be Selector (from group), second should be direct check_unused
    assert isinstance(endpoint_seq.children[0], Selector)
```

- [ ] **Step 2: Run CheckAdapter tests — verify they fail**

```bash
python -m pytest tests/test_bt_adapters.py -v --tb=short
```

- [ ] **Step 3: Add CheckAdapter to adapters.py**

Add to `websec_test/engine/adapters.py`:

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

- [ ] **Step 4: Create builder.py**

Create `websec_test/engine/builder.py`:

```python
"""CheckTreeBuilder — builds check-level behavior trees from module classes.

Auto-discovers check_* methods and SELECTOR_GROUPS on module instances.
Convention over configuration: no @register decorator needed.
"""
import inspect
from .nodes import Sequence, Selector
from .decorators import Retry
from .adapters import CheckAdapter


class CheckTreeBuilder:
    @staticmethod
    def build(module_instance, module_name, endpoints):
        named_endpoints = []
        for ep in endpoints:
            path = getattr(ep, 'url', None) or getattr(ep, 'path', None) or str(ep)
            named_endpoints.append((path, ep))
        children = []
        selector_groups = getattr(module_instance, 'SELECTOR_GROUPS', {})
        check_methods = [(name, fn) for name, fn in
                         inspect.getmembers(module_instance, inspect.ismethod)
                         if name.startswith('check_')]
        check_names = {name for name, _ in check_methods}
        used = set()
        for path, endpoint in named_endpoints:
            endpoint_children = []
            for group_name, check_list in selector_groups.items():
                group_children = []
                for cn in check_list:
                    fn = getattr(module_instance, cn, None)
                    if fn:
                        group_children.append(Retry(f"{cn}", CheckAdapter(cn, fn, endpoint), max_retries=1))
                        used.add(cn)
                if group_children:
                    endpoint_children.append(Selector(group_name, group_children))
            for name, fn in check_methods:
                if name not in used:
                    endpoint_children.append(Retry(name, CheckAdapter(name, fn, endpoint), max_retries=1))
            children.append(Sequence(str(path), endpoint_children))
        return Sequence(module_name, children)
```

- [ ] **Step 5: Update engine/__init__.py exports**

Edit `websec_test/engine/__init__.py`:

```
Old:
from .adapters import ModuleAdapter

New:
from .adapters import ModuleAdapter, CheckAdapter
from .builder import CheckTreeBuilder
```

- [ ] **Step 6: Run CheckAdapter tests — verify they pass**

```bash
python -m pytest tests/test_bt_adapters.py -v --tb=short
```

- [ ] **Step 7: Run ALL tests — verify nothing broken**

```bash
python -X utf8 -m pytest tests/ --tb=short -q --ignore=tests/test_integration.py --ignore=tests/test_integration_live.py
```

- [ ] **Step 8: Commit**

```bash
git add websec_test/engine/adapters.py websec_test/engine/builder.py websec_test/engine/__init__.py tests/test_bt_adapters.py
git commit -m "feat: add CheckAdapter, CheckTreeBuilder for check-level BT"
```

---

### Task 3: Module Reorganization + Loader + main.py

**Files:**
- Create: `websec_test/modules/authentication/__init__.py`
- Create: `websec_test/modules/injection/__init__.py`
- Create: `websec_test/modules/configuration/__init__.py`
- Move: `auth.py` → `websec_test/modules/authentication/auth.py`
- Move: `authz.py` → `websec_test/modules/authentication/authz.py`
- Move: `csrf.py` → `websec_test/modules/authentication/csrf.py`
- Move: `sqli.py` → `websec_test/modules/injection/sqli.py`
- Move: `xss.py` → `websec_test/modules/injection/xss.py`
- Move: `nosql.py` → `websec_test/modules/injection/nosql.py`
- Move: `cmd_injection.py` → `websec_test/modules/injection/cmd_injection.py`
- Move: `headers.py` → `websec_test/modules/configuration/headers.py`
- Move: `cookies.py` → `websec_test/modules/configuration/cookies.py`
- Move: `ssl_tls.py` → `websec_test/modules/configuration/ssl_tls.py`
- Move: `cors.py` → `websec_test/modules/configuration/cors.py`
- Move: `disclosure.py` → `websec_test/modules/configuration/disclosure.py`
- Move: `methods.py` → `websec_test/modules/configuration/methods.py`
- Delete: all old flat module files
- Modify: `websec_test/engine/loader.py` — use `walk_packages` for subfolder discovery
- Modify: `websec_test/main.py` — use CheckTreeBuilder in run()

**Interfaces:**
- Consumes: module classes in new locations; CheckTreeBuilder from engine
- Produces: module names include subfolder prefix (e.g. `authentication.auth`, `injection.sqli`), backward-compat short names

- [ ] **Step 1: Create subfolder init files**

Create `websec_test/modules/authentication/__init__.py`:
```python
from .auth import AuthModule
from .authz import AuthorizationModule
from .csrf import CSRFModule
__all__ = ["AuthModule", "AuthorizationModule", "CSRFModule"]
```

Create `websec_test/modules/injection/__init__.py`:
```python
from .sqli import SqliModule
from .xss import XssModule
from .nosql import NosqlModule
from .cmd_injection import CmdInjectionModule
__all__ = ["SqliModule", "XssModule", "NosqlModule", "CmdInjectionModule"]
```

Create `websec_test/modules/configuration/__init__.py`:
```python
from .headers import HeadersModule
from .cookies import CookiesModule
from .ssl_tls import SslTlsModule
from .cors import CorsModule
from .disclosure import DisclosureModule
from .methods import MethodsModule
__all__ = ["HeadersModule", "CookiesModule", "SslTlsModule", "CorsModule", "DisclosureModule", "MethodsModule"]
```

- [ ] **Step 2: Move files to subfolders**

Use git mv for each file:

```bash
mkdir websec_test/modules/authentication websec_test/modules/injection websec_test/modules/configuration
git mv websec_test/modules/auth.py websec_test/modules/authentication/auth.py
git mv websec_test/modules/authz.py websec_test/modules/authentication/authz.py
git mv websec_test/modules/csrf.py websec_test/modules/authentication/csrf.py
git mv websec_test/modules/sqli.py websec_test/modules/injection/sqli.py
git mv websec_test/modules/xss.py websec_test/modules/injection/xss.py
git mv websec_test/modules/nosql.py websec_test/modules/injection/nosql.py
git mv websec_test/modules/cmd_injection.py websec_test/modules/injection/cmd_injection.py
git mv websec_test/modules/headers.py websec_test/modules/configuration/headers.py
git mv websec_test/modules/cookies.py websec_test/modules/configuration/cookies.py
git mv websec_test/modules/ssl_tls.py websec_test/modules/configuration/ssl_tls.py
git mv websec_test/modules/cors.py websec_test/modules/configuration/cors.py
git mv websec_test/modules/disclosure.py websec_test/modules/configuration/disclosure.py
git mv websec_test/modules/methods.py websec_test/modules/configuration/methods.py
```

- [ ] **Step 3: Update loader.py for subfolder discovery**

Replace `websec_test/engine/loader.py` with:

```python
"""Plugin loader — auto-discovers security modules from websec_test/modules/
and its subpackages (authentication/, injection/, configuration/).
"""
import importlib
import inspect
import pkgutil

import websec_test.modules as pkg


def discover_modules():
    module_names = []
    module_factories = {}
    for importer, modname, ispkg in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
        if ispkg:
            continue
        parts = modname.split(".")
        local_name = ".".join(parts[2:])  # strip "websec_test.modules." prefix
        if parts[-1].startswith("_"):
            continue
        try:
            mod = importlib.import_module(modname)
        except Exception as e:
            print(f"[!] Failed to load module '{local_name}': {e}")
            continue
        module_class = None
        for name, obj in inspect.getmembers(mod, inspect.isclass):
            local_cls_name = parts[-1].capitalize() + "Module"
            if name == local_cls_name:
                module_class = obj
                break
        if module_class is None:
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if hasattr(obj, "discover") and hasattr(obj, "test"):
                    module_class = obj
                    break
        if module_class is None:
            continue
        module_names.append(local_name)
        module_factories[local_name] = module_class
    module_names.sort()
    return module_names, module_factories
```

- [ ] **Step 4: Update main.py to use CheckTreeBuilder**

Edit `websec_test/main.py`:

Change import line:
```
Old: from websec_test.engine import Sequence, ModuleAdapter, Blackboard
New: from websec_test.engine import Sequence, ModuleAdapter, Blackboard, CheckTreeBuilder
```

Change the tree-building block (lines 142-145):
```
Old:
    children = [ModuleAdapter(name, mod) for name, mod in module_map.items()]
    root = Sequence("scan", children=children)
    root.tick(blackboard)

New:
    children = []
    for name, mod in module_map.items():
        has_checks = any(m.startswith("check_") for m in dir(mod))
        if has_checks:
            endpoints = mod.discover(client, target)
            tree = CheckTreeBuilder.build(mod, name, endpoints)
            children.append(tree)
        else:
            children.append(ModuleAdapter(name, mod))
    root = Sequence("scan", children=children)
    root.tick(blackboard)
```

- [ ] **Step 5: Run tests — verify they pass after reorg**

```bash
python -X utf8 -m pytest tests/ --tb=short -q --ignore=tests/test_integration.py --ignore=tests/test_integration_live.py
```
Expected: ~185 passed (tests import modules by old paths — they'll fail because files moved)

Fix test imports: update all test files that import from `websec_test.modules.*` to use new paths.

For each test file, change:
```
Old: from websec_test.modules.headers import HeadersModule
New: from websec_test.modules.configuration.headers import HeadersModule
```

Module files affected by import changes:
- `tests/test_headers.py` → `from websec_test.modules.configuration.headers import HeadersModule`
- `tests/test_auth.py` → `from websec_test.modules.authentication.auth import AuthModule`
- `tests/test_csrf.py` → `from websec_test.modules.authentication.csrf import CSRFModule`
- `tests/test_sqli.py` → `from websec_test.modules.injection.sqli import SqliModule`
- `tests/test_xss.py` → `from websec_test.modules.injection.xss import XssModule`
- `tests/test_nosql.py` → `from websec_test.modules.injection.nosql import NosqlModule`
- `tests/test_cmd_injection.py` → `from websec_test.modules.injection.cmd_injection import CmdInjectionModule`
- `tests/test_authz.py` → `from websec_test.modules.authentication.authz import AuthorizationModule`
- `tests/test_cors.py` → `from websec_test.modules.configuration.cors import CorsModule`
- `tests/test_cookies.py` → `from websec_test.modules.configuration.cookies import CookiesModule`
- `tests/test_disclosure.py` → `from websec_test.modules.configuration.disclosure import DisclosureModule`
- `tests/test_methods.py` → `from websec_test.modules.configuration.methods import MethodsModule`
- `tests/test_ssl_tls.py` → `from websec_test.modules.configuration.ssl_tls import SslTlsModule`

Also update `test_bt_adapters.py` (references `websec_test.modules.headers.HeadersModule`).

- [ ] **Step 6: Run tests again**

```bash
python -X utf8 -m pytest tests/ --tb=short -q --ignore=tests/test_integration.py --ignore=tests/test_integration_live.py
```
Expected: ~185 passed

- [ ] **Step 7: Commit**

```bash
git add websec_test/modules/ websec_test/engine/loader.py websec_test/main.py tests/
git commit -m "refactor: reorganize modules into subfolders, update loader, integrate CheckTreeBuilder"
```

---

### Task 4: Migrate All Modules to check_* Methods

**Files:** All 14 module files in new subfolders

For each module, split `test(client, target, endpoints)` into individual `check_*(client, target, endpoint)` methods and add `SELECTOR_GROUPS` where applicable.

All modules share this migration pattern:
1. Keep `discover()` method as-is
2. Remove `test()` method
3. For each loop iteration/check in `test()`, create a `check_<name>(self, client, target, endpoint)` method
4. Each `check_*` returns a single `TestResult`

Below are the migrated versions for all 14 modules.

- [ ] **Step 1: Migrate headers.py**

Update `websec_test/modules/configuration/headers.py`:

Replace the `test()` method with individual `check_*` methods. Keep `HEADER_CHECKS` dict and `discover()` as-is.

```python
    def test(self, client, target, endpoints):
        """Legacy test method — kept for ModuleAdapter backward compat."""
        return [self._check_single(client, target, ep, header, info)
                for ep in endpoints
                for header, info in HEADER_CHECKS.items()]

    def _check_single(self, client, target, endpoint, header, info):
        try:
            resp = client.get(getattr(endpoint, 'url', str(endpoint)))
        except Exception as e:
            return TestResult(module="headers",
                test_name=f"check_{header.replace('-', '_').lower()}",
                status=TestStatus.ERROR, severity=info["severity"],
                endpoint=getattr(endpoint, 'url', str(endpoint)),
                evidence=f"Request failed: {e}", recommendation=info["recommendation"])
        if header in resp.headers:
            return TestResult(module="headers",
                test_name=f"check_{header.replace('-', '_').lower()}",
                status=TestStatus.PASS, severity=info["severity"],
                endpoint=getattr(endpoint, 'url', str(endpoint)),
                evidence=f"{header}: {resp.headers[header]}", recommendation=info["recommendation"])
        return TestResult(module="headers",
            test_name=f"check_{header.replace('-', '_').lower()}",
            status=TestStatus.FAIL, severity=info["severity"],
            endpoint=getattr(endpoint, 'url', str(endpoint)),
            evidence=f"Missing '{header}' header", recommendation=info["recommendation"])
```

Then add individual check methods — one per header. Each delegates to `_check_single`:

```python
    def check_strict_transport_security(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Strict-Transport-Security", HEADER_CHECKS["Strict-Transport-Security"])
    def check_content_security_policy(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Content-Security-Policy", HEADER_CHECKS["Content-Security-Policy"])
    def check_x_frame_options(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "X-Frame-Options", HEADER_CHECKS["X-Frame-Options"])
    def check_x_content_type_options(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "X-Content-Type-Options", HEADER_CHECKS["X-Content-Type-Options"])
    def check_referrer_policy(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Referrer-Policy", HEADER_CHECKS["Referrer-Policy"])
    def check_permissions_policy(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Permissions-Policy", HEADER_CHECKS["Permissions-Policy"])
    def check_cross_origin_opener_policy(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Cross-Origin-Opener-Policy", HEADER_CHECKS["Cross-Origin-Opener-Policy"])
    def check_cross_origin_resource_policy(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Cross-Origin-Resource-Policy", HEADER_CHECKS["Cross-Origin-Resource-Policy"])
```

- [ ] **Step 2: Migrate cookies.py**

Same pattern as headers: replace `test()` with per-flag `check_*` methods + keep `legacy test()`.

- [ ] **Step 3: Migrate ssl_tls.py**

Replace `test()` with:
```python
    def check_certificate_valid(self, client, target, endpoint):
        return self._check_certificate(endpoint.host, endpoint.port)[0]
    def check_weak_protocol_tls_1_0(self, client, target, endpoint):
        return self._check_weak_protocols(endpoint.host, endpoint.port)[0]
    def check_hsts_preload(self, client, target, endpoint):
        return self._check_hsts_preload(client)
```

- [ ] **Step 4: Migrate cors.py**

Replace `test()` with per-check methods: `check_wildcard_origin`, `check_credentials_with_wildcard`, `check_reflected_origin`.

- [ ] **Step 5: Migrate disclosure.py**

Replace `test()` with per-check methods: `check_info_header_server`, `check_info_header_x_powered_by` (etc.), `check_directory_listing`, `check_stack_trace_error`.

- [ ] **Step 6: Migrate methods.py**

Replace `test()` with per-check methods: `check_options_allow_enumeration`, `check_trace_method_enabled`, `check_put_method_enabled`, `check_delete_method_enabled`, `check_verb_tampering`.

- [ ] **Step 7: Migrate auth.py**

Replace `test()` with per-check methods: `check_blank_password_login`, `check_sqli_login_bypass`, `check_rate_limiting`, `check_username_enumeration`. Add `SELECTOR_GROUPS = {"sqli_techniques": ["check_sqli_login_bypass"]}`.

- [ ] **Step 8: Migrate authz.py**

Replace `test()` with per-check methods: `check_forced_browsing`, `check_idor_check`.

- [ ] **Step 9: Migrate csrf.py**

Replace `test()` with per-check methods: `check_missing_csrf_token`, `check_csrf_token_reuse`.

- [ ] **Step 10: Migrate sqli.py**

Replace `test()` with per-check methods: `check_sqli_detection`. Add `SELECTOR_GROUPS = {"sqli_techniques": ["check_sqli_detection_error_based", ...]}` as needed.

- [ ] **Step 11: Migrate xss.py, nosql.py, cmd_injection.py**

Same pattern: `check_*` methods wrapping existing logic.

Each migration step should be followed by running the module's specific tests and then all tests:

```bash
python -m pytest tests/test_headers.py -v --tb=short
python -X utf8 -m pytest tests/ --tb=short -q --ignore=tests/test_integration.py --ignore=tests/test_integration_live.py
```

- [ ] **Step 12: Final run — all tests pass**

```bash
python -X utf8 -m pytest tests/ --tb=short -q --ignore=tests/test_integration.py --ignore=tests/test_integration_live.py
```

- [ ] **Step 13: Commit**

```bash
git add websec_test/modules/ tests/
git commit -m "refactor: migrate all modules to check_* method convention"
```

---

### Task 5: DevSecOps CI/CD Pipeline Fix

**Files:**
- Create: `scripts/security_scanner.py`
- Create: `scripts/vulnerability_assessor.py`
- Create: `scripts/compliance_checker.py`
- Modify: `.github/workflows/security-scan.yml`
- Create: `Dockerfile`

- [ ] **Step 1: Create security_scanner.py wrapper**

Create `scripts/security_scanner.py`:

```python
#!/usr/bin/env python3
"""Thin CLI wrapper for websec_test.security.scanner.SecurityScanner."""
import sys, json, argparse
from websec_test.security.scanner import SecurityScanner

def main():
    parser = argparse.ArgumentParser(description="SAST security scanner")
    parser.add_argument("path", nargs="?", default=".", help="Project path")
    parser.add_argument("--severity", default="high", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()
    scanner = SecurityScanner(args.path, min_severity=args.severity)
    findings = scanner.scan()
    if args.json:
        data = [{"file": f.file_path, "line": f.line_number, "severity": f.severity,
                 "category": f.category, "evidence": f.evidence} for f in findings]
        output = json.dumps(data, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)
    else:
        for f in findings:
            print(f"[{f.severity.upper()}] {f.file_path}:{f.line_number}  {f.category}: {f.evidence[:100]}")
        print(f"Summary: {len(findings)} findings")
    sys.exit(scanner.exit_code(findings))

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Create vulnerability_assessor.py wrapper**

Same pattern, delegates to `websec_test.security.assessor.VulnerabilityAssessor`:
```python
#!/usr/bin/env python3
from websec_test.security.assessor import VulnerabilityAssessor
# ... argparse and delegate to assessor.assess()
```

- [ ] **Step 3: Create compliance_checker.py wrapper**

Same pattern, delegates to `websec_test.security.checker.ComplianceChecker`:
```python
#!/usr/bin/env python3
from websec_test.security.checker import ComplianceChecker
# ... argparse and delegate to checker.check()
```

- [ ] **Step 4: Fix security-scan.yml**

Edit `.github/workflows/security-scan.yml`:

```
Change:
  pip install -r requirements.txt
To:
  pip install -e ".[dev]"

Change:
  python scripts/security_scanner.py . --severity high
To:
  python scripts/security_scanner.py . --severity high

(The script paths are now correct — wrappers exist at scripts/*.py)

Add fail-fast: false to nightly-audit job:

jobs:
  security-gate:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11"]
      fail-fast: false
```

- [ ] **Step 5: Create Dockerfile**

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -e ".[dev]"
ENTRYPOINT ["python", "-m", "websec_test.main"]
```

- [ ] **Step 6: Commit**

```bash
git add scripts/ .github/workflows/security-scan.yml Dockerfile
git commit -m "feat: DevSecOps CI/CD — fix security-scan.yml, add wrapper scripts and Dockerfile"
```

---

### Task 6: Final Verification

- [ ] **Step 1: Run full test suite**

```bash
python -X utf8 -m pytest tests/ --tb=short -q --ignore=tests/test_integration.py --ignore=tests/test_integration_live.py
```

- [ ] **Step 2: Verify CLI works**

```bash
python -m websec_test.main --help
python -m websec_test.main --secops .
python -m websec_test.main --target http://localhost:8080 --discover 2>&1 || true
```

- [ ] **Step 3: Verify loader discovers subfolder modules**

```bash
python -c "from websec_test.engine.loader import discover_modules; names, _ = discover_modules(); print(sorted(names))"
```
Expected output includes: `authentication.auth`, `authentication.authz`, `authentication.csrf`, `injection.sqli`, `configuration.headers`, etc.

- [ ] **Step 4: Verify backward compat — short module names**

Old test files import `from websec_test.modules.configuration.headers import HeadersModule` — verify the `__init__.py` re-exports work:

```bash
python -c "from websec_test.modules.configuration.headers import HeadersModule; print('OK')"
```

- [ ] **Step 5: Commit any remaining fixes**

```bash
git add -A
git commit -m "chore: final cleanup and verification"
```

---

### Task 7: Pen-Testing Skill Alignment

**Files:**
- Create: `scripts/vulnerability_scanner.py` — thin re-export of assessor
- Create: `scripts/dependency_auditor.py` — dependency audit CLI
- Create: `scripts/pentest_report_generator.py` — CVSS report from findings
- Modify: `websec_test/results/models.py` — add cvss_score, cvss_vector to TestResult
- Modify: `websec_test/main.py` — add --scope flag
- Create: `references/owasp_top_10_checklist.md`
- Create: `references/attack_patterns.md`
- Create: `references/responsible_disclosure.md`

- [ ] **Step 1: Add CVSS fields to TestResult**

Edit `websec_test/results/models.py`. Add optional fields to TestResult dataclass:

```python
@dataclass
class TestResult:
    ...
    cvss_score: float | None = None
    cvss_vector: str | None = None
```

- [ ] **Step 2: Create vulnerability_scanner.py**

Create `scripts/vulnerability_scanner.py` — delegates to `VulnerabilityAssessor`:

```python
#!/usr/bin/env python3
"""Thin CLI wrapper — pen-testing skill compat."""
import sys, json, argparse
from websec_test.security.assessor import VulnerabilityAssessor

def main():
    parser = argparse.ArgumentParser(description="Vulnerability scanner")
    parser.add_argument("--target", help="Target URL or project path")
    parser.add_argument("--scope", default="quick", choices=["quick", "full"])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()
    path = args.target or "."
    assessor = VulnerabilityAssessor(path, min_severity="high" if args.scope == "quick" else "low")
    result = assessor.assess()
    if args.json:
        data = {"count": result.count, "risk_score": result.risk_score,
                "vulnerabilities": [{"cve_id": v.cve_id, "package": v.package,
                    "severity": v.severity, "cvss": v.cvss_score} for v in result.vulnerabilities]}
        output = json.dumps(data, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)
    else:
        print(f"Vulnerabilities: {result.count}, Risk score: {result.risk_score:.1f}")
    sys.exit(assessor.exit_code(result))

if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Create dependency_auditor.py**

Same pattern — delegates to assessor with focus on dependency analysis from a file manifest:

```python
#!/usr/bin/env python3
"""Dependency auditor — scans package manifests for known CVEs."""
import sys, json, argparse
from websec_test.security.assessor import VulnerabilityAssessor

def main():
    parser = argparse.ArgumentParser(description="Dependency vulnerability auditor")
    parser.add_argument("--file", required=True, help="Path to package manifest")
    parser.add_argument("--severity", default="high", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()
    assessor = VulnerabilityAssessor(args.file, min_severity=args.severity)
    result = assessor.assess()
    if args.json:
        data = [{"cve_id": v.cve_id, "package": v.package, "installed": v.installed_version,
                 "fixed": v.fixed_version, "cvss": v.cvss_score} for v in result.vulnerabilities]
        output = json.dumps(data, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)
    else:
        for v in result.vulnerabilities:
            print(f"[{v.severity.upper()}] {v.cve_id} in {v.package} {v.installed_version}")
        print(f"Total: {result.count}")
    sys.exit(assessor.exit_code(result))

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Create pentest_report_generator.py**

Creates markdown reports from JSON findings:

```python
#!/usr/bin/env python3
"""Generate penetration test reports from findings JSON."""
import sys, json, argparse
from datetime import datetime

SEVERITY_CVSS = {"info": 0.0, "low": 3.5, "medium": 5.5, "high": 7.5, "critical": 9.5}

def generate_markdown(findings):
    lines = ["# Penetration Test Report", f"**Generated:** {datetime.now().isoformat()}", "",
             "## Executive Summary", f"**Total findings:** {len(findings)}", ""]
    for f in findings:
        sev = f.get("severity", "medium").upper()
        cvss = f.get("cvss_score") or SEVERITY_CVSS.get(f.get("severity", "medium"), 5.0)
        lines.append(f"### [{sev}] {f.get('title', 'Untitled')}")
        lines.append(f"**CVSS:** {cvss}  |  **Category:** {f.get('category', 'N/A')}")
        lines.append(f"**Description:** {f.get('description', f.get('evidence', 'N/A'))[:200]}")
        lines.append(f"**Remediation:** {f.get('remediation', 'N/A')}")
        lines.append("")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Pen test report generator")
    parser.add_argument("--findings", required=True, help="Findings JSON file")
    parser.add_argument("--format", default="md", choices=["md", "json"])
    parser.add_argument("--output", default="pentest-report.md", help="Output file path")
    args = parser.parse_args()
    with open(args.findings, "r", encoding="utf-8") as f:
        findings = json.load(f)
    if args.format == "json":
        output = json.dumps(findings, indent=2)
    else:
        output = generate_markdown(findings)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(output)
    print(f"Report written to {args.output}")

if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Add --scope flag to CLI**

Edit `websec_test/main.py` parse_args(). Add after existing --modules flag:

```python
    parser.add_argument("--scope", choices=["quick", "full", "api"],
                        help="Quick (headers/cookies/ssl), full (all), or API-focused modules")
```

In the parsing logic, map scope to module subset:

```python
    if args.scope == "quick":
        args.modules = [m for m in ALL_MODULES if m.startswith(("configuration.", "injection.sqli"))]
    elif args.scope == "api":
        args.modules = [m for m in ALL_MODULES if m.startswith(("authentication.", "injection."))]
    elif args.scope == "full":
        args.modules = ALL_MODULES
```

This goes after `if args.all: args.modules = ALL_MODULES`.

- [ ] **Step 6: Create reference docs**

Create `references/owasp_top_10_checklist.md`, `references/attack_patterns.md`, `references/responsible_disclosure.md`.

These are documented in design spec `2026-06-20-reference-docs-design.md` (commit 648ec16). Read that spec and extract content per section into the three markdown files. Each file must cover what the pen-testing skill references:
- `owasp_top_10_checklist.md` — OWASP A01-A10 with test procedures per category
- `attack_patterns.md` — JWT manipulation, SQLi per engine, SSRF bypass, XSS filter evasion
- `responsible_disclosure.md` — 90-day timeline, communication templates

- [ ] **Step 7: Run full test suite**

```bash
python -X utf8 -m pytest tests/ --tb=short -q --ignore=tests/test_integration.py --ignore=tests/test_integration_live.py
```

- [ ] **Step 8: Commit**

```bash
git add scripts/ websec_test/results/models.py websec_test/main.py references/
git commit -m "feat: pen-testing skill alignment — CVSS, scope flag, reference docs, wrappers"
```
