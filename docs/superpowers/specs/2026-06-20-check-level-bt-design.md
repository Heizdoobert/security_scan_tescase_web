---
date: 2026-06-20
topic: "WebSec Test — Check-Level Behavior Trees (BT Phase 2)"
status: draft
---

## Problem Statement

The current Behavior Tree engine operates at the **module level** — one `ModuleAdapter` wraps an entire module's `discover()` + `test()` into a single opaque tick. This means:

- **No per-check granularity** — you can't see which specific check failed inside a module
- **No per-check control flow** — you can't retry just the HSTS check, skip CSP if HSTS failed, or run 8 header checks in parallel
- **No check-level conditions** — gate an injection check on "did we find forms?"
- **All-or-nothing result semantics** — a module returns SUCCESS/FAILURE for its entire batch of checks

We already have the module-level BT infrastructure. Now we need to decompose *inside* modules so that individual checks become first-class BT nodes.

## Constraints

- **Existing `ModuleAdapter` continues to work** — no breaking changes to existing tree compositions
- **All 184 existing tests must still pass** — additive changes only
- **Check functions are simple callables** — `(client, target, blackboard) -> TestResult`
- **Modules can opt in gradually** — migrating one module at a time is fine
- **No new Python dependencies**
- **Backward-compatible default** — `build_tree()` still produces ModuleAdapter-based trees unless the user explicitly requests check-level trees

## Approach

Introduce a **`CheckAdapter`** node that wraps a single check function, plus a **`CheckTreeBuilder`** that composes check-level trees from module metadata. Modules declare their checks as a list of `CheckSpec` descriptors — name, function, severity, dependencies.

This gives us per-check nodes while keeping module code clean:

```
ModuleAdapter("headers", HeadersModule())    ← still works, opaque
CheckTreeBuilder.build(HEADER_CHECKS_SPEC)   ← new: decomposable tree
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Check-Level BT Tree                      │
│                                                             │
│  Sequence("headers_scan")                                   │
│    ├── DiscoverAction("/")           ← discover endpoints   │
│    └── Parallel("check_headers")     ← independent checks   │
│          ├── CheckAdapter("hsts")                            │
│          ├── CheckAdapter("csp")                             │
│          ├── CheckAdapter("x_frame_options")                 │
│          ├── CheckAdapter("x_content_type_options")           │
│          ├── CheckAdapter("referrer_policy")                 │
│          ├── CheckAdapter("permissions_policy")               │
│          ├── CheckAdapter("cross_origin_opener_policy")       │
│          └── CheckAdapter("cross_origin_resource_policy")     │
└─────────────────────────────────────────────────────────────┘
```

### Key difference from Phase 1

| Aspect | Module-Level (Phase 1) | Check-Level (Phase 2) |
|--------|----------------------|----------------------|
| Node granularity | One `ModuleAdapter` per module | One `CheckAdapter` per check |
| Composite structure | `Sequence` of modules | `Sequence` of `Parallel` check groups |
| Control flow | Module succeeds/fails as a batch | Each check can be retried/gated individually |
| Inspectability | Opaque — all checks run together | Transparent — each check tick is visible |
| Backward compat | Default | Opt-in via `CheckTreeBuilder` |

## Components

### 1. CheckAdapter (`adapters.py`)

A new `Action` subclass that wraps a single check function:

```python
class CheckAdapter(Action):
    def __init__(self, name, check_fn, module_name=""):
        super().__init__(name)
        self.check_fn = check_fn      # (client, target, blackboard) -> TestResult
        self.module_name = module_name or name

    def do_tick(self, blackboard):
        result = self.check_fn(blackboard.client, blackboard.target, blackboard)
        if result:
            blackboard.add_result(result)
        has_failure = result and result.status in (TestStatus.FAIL, TestStatus.ERROR)
        return NodeStatus.FAILURE if has_failure else NodeStatus.SUCCESS
```

The `check_fn` signature is intentionally simple:
- **Input:** `client` (SessionClient), `target` (str), `blackboard` (for reading shared state like discovered endpoints)
- **Output:** a single `TestResult`
- **Side effects:** the function handles its own HTTP requests via `client`
- **Exception handling:** `Action.do_tick` already wraps exceptions → `NodeStatus.FAILURE`

### 2. CheckSpec

A lightweight descriptor that declares a check's metadata:

```python
@dataclass
class CheckSpec:
    name: str                  # e.g. "check_strict_transport_security"
    fn: Callable               # check function
    severity: Severity         # from module metadata
    depends_on: list[str] | None = None  # optional: checks that must pass first
    module_name: str = ""       # module namespace for TestResult
```

### 3. CheckTreeBuilder

A utility that takes a list of `CheckSpec` and builds a composite tree:

```python
class CheckTreeBuilder:
    @staticmethod
    def build_module(module_name: str, discover_fn, checks: list[CheckSpec]) -> Sequence:
        """Build a check-level tree for a module."""
        discover_node = DiscoverAction(f"{module_name}_discover", discover_fn)
        # If checks are independent → Parallel
        # If checks have dependencies → group into sequences
        check_nodes = [CheckAdapter(spec.name, spec.fn, module_name) for spec in checks]
        # Split into dependency groups
        groups = CheckTreeBuilder._group_by_dependency(checks, check_nodes)
        if len(groups) == 1:
            check_group = Parallel(f"{module_name}_checks", children=groups[0], min_success=0)
        else:
            check_group = Sequence(f"{module_name}_checks", children=[
                Parallel(f"group_{i}", children=group, min_success=0)
                for i, group in enumerate(groups)
            ])
        return Sequence(module_name, children=[discover_node, check_group])

    @staticmethod
    def _group_by_dependency(specs, nodes):
        """Topological sort: group independent checks together."""
        # Simple approach: checks without deps = group 0
        # checks that depend on group 0 = group 1, etc.
        ...
```

### 4. DiscoverAction

A new leaf for module-level discovery as a standalone node:

```python
class DiscoverAction(Action):
    def __init__(self, name, discover_fn):
        super().__init__(name)
        self.discover_fn = discover_fn

    def do_tick(self, blackboard):
        endpoints = self.discover_fn(blackboard.client, blackboard.target)
        blackboard.set(f"{self.name}_endpoints", endpoints)
        return NodeStatus.SUCCESS if endpoints else NodeStatus.FAILURE
```

Separating discovery from checks means check functions can read discovered endpoints from the blackboard.

## Module Migration Strategy

Each module gets migrated by:
1. Extracting individual check functions from `test()` into standalone `check_*` functions
2. Declaring a `CHECKS_SPEC` list using `CheckSpec`
3. Optionally keeping the original `test()` method (backs the `ModuleAdapter` path)

### Example: HeadersModule

```python
# Existing HEADER_CHECKS dict stays
# New: standalone check functions
def _check_header(client, target, blackboard, header_name, info):
    """Check if a single header is present."""
    endpoints = blackboard.get("headers_discover_endpoints", [Endpoint("/", "GET")])
    ep = endpoints[0]
    try:
        resp = client.get(ep.url)
    except RequestException as e:
        return TestResult(module="headers", test_name=f"check_{header_name}",
                          status=TestStatus.ERROR, severity=info["severity"],
                          endpoint=ep.url, evidence=str(e),
                          recommendation=info["recommendation"])
    present = header_name in resp.headers
    return TestResult(module="headers", test_name=f"check_{header_name}",
                      status=TestStatus.PASS if present else TestStatus.FAIL,
                      severity=info["severity"], endpoint=ep.url,
                      evidence=f"{header_name}: {resp.headers.get(header_name, 'MISSING')}",
                      recommendation=info["recommendation"])

# Factory function: creates CheckSpec for each header
def headers_check_specs():
    return [
        CheckSpec(name=f"check_{h.replace('-', '_').lower()}",
                  fn=lambda c, t, b, h=h, i=i: _check_header(c, t, b, h, i),
                  severity=i["severity"], module_name="headers")
        for h, i in HEADER_CHECKS.items()
    ]
```

### Example: AuthModule

The AuthModule has 4 checks with different dependency levels:

```python
def auth_check_specs():
    return [
        CheckSpec("blank_password_login", _check_blank_password, ...),
        CheckSpec("sqli_login_bypass", _check_sqli_bypass,
                  depends_on=["blank_password_login"]),  # needs form discovery first
        CheckSpec("rate_limiting", _check_rate_limiting,
                  depends_on=["blank_password_login"]),
        CheckSpec("username_enumeration", _check_username_enum,
                  depends_on=["blank_password_login"]),
    ]
```

This produces:

```
Sequence("auth")
  ├── DiscoverAction("auth_discover")  → stores endpoints on blackboard
  └── Sequence("auth_checks_deps")
        ├── CheckAdapter("blank_password_login")
        └── Parallel("auth_independent")
              ├── CheckAdapter("sqli_login_bypass")
              ├── CheckAdapter("rate_limiting")
              └── CheckAdapter("username_enumeration")
```

## Data Flow

```
main.py
  → CheckTreeBuilder.build_module("headers", discover, specs)
    → Sequence("headers")
        → DiscoverAction("headers_discover")
            → HeadersModule.discover(client, target)
            → stores Endpoint[] on blackboard
            → returns SUCCESS
        → Parallel("headers_checks")
            → CheckAdapter("hsts")
                → _check_header(client, target, blackboard)
                → reads endpoints from blackboard
                → makes HTTP request via client
                → creates TestResult
                → blackboard.add_result(result)
                → returns SUCCESS/FAILURE
            → CheckAdapter("csp")  ← runs in parallel with hsts
                → (same pattern)
            → ... (6 more header checks, all parallel)
    → blackboard.results → ResultCollector → Reporter
```

## Integration with main.py

`build_tree()` gets an optional parameter to use check-level trees:

```python
def build_tree(module_names, args, check_level=False):
    nodes = []
    for name in module_names:
        module = create_module(name, args)
        if check_level and has_check_specs(name):
            # Use check-level tree
            from websec_test.engine.builder import CheckTreeBuilder, check_registry
            spec_list = check_registry[name]()
            discover_fn = module.discover
            tree = CheckTreeBuilder.build_module(name, discover_fn, spec_list)
            nodes.append(tree)
        else:
            # Use module-level tree (backward compatible)
            nodes.append(ModuleAdapter(name, module))
    return Sequence("websec_scan", children=nodes)
```

The default remains `check_level=False` — backward compatible. Users opt in with `check_level=True` in their tree composition, or we can flip the default later once all 10 modules are migrated.

## Check Registry

A central registry (`engine/registry.py`) that maps module names to their `CheckSpec` producers:

```python
# websec_test/engine/registry.py

check_registry: dict[str, Callable[[], list[CheckSpec]]] = {}

def register(module_name: str):
    """Decorator to register a check spec factory."""
    def wrapper(fn):
        check_registry[module_name] = fn
        return fn
    return wrapper
```

Modules register their specs:

```python
@register("headers")
def headers_check_specs():
    return [CheckSpec(...), ...]
```

This keeps the registry decoupled — modules don't import engine internals, they just export a `register`-decorated function.

## What We're Building

| File | What |
|------|------|
| `engine/adapters.py` | Add `CheckAdapter`, `DiscoverAction` |
| `engine/builder.py` (new) | `CheckSpec`, `CheckTreeBuilder`, dependency grouping |
| `engine/registry.py` (new) | `check_registry`, `register()` |
| `engine/__init__.py` | Export new types |
| `modules/headers.py` | Extract per-header check functions, add `headers_check_specs()` |
| `modules/auth.py` | Extract per-check functions, add `auth_check_specs()` |
| `modules/cors.py` | Extract per-check functions, add `cors_check_specs()` |
| `main.py` | Add `--check-level` flag, optional check-tree mode |
| `tests/test_bt_check_adapter.py` (new) | CheckAdapter unit tests |
| `tests/test_bt_builder.py` (new) | CheckTreeBuilder + dependency grouping tests |
| `tests/test_bt_checks_headers.py` (new) | Check-level headers integration |
| `tests/test_bt_checks_auth.py` (new) | Check-level auth integration |
| `tests/test_bt_checks_cors.py` (new) | Check-level CORS integration |

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Check function raises exception | `Action.do_tick` catches → `NodeStatus.FAILURE`, `TestResult(status=ERROR)` added |
| Check function returns `None` | `CheckAdapter` returns `SUCCESS` (skip/no-op) |
| Discovery finds no endpoints | `DiscoverAction` returns `FAILURE`, check nodes read empty list from blackboard |
| Dependency check failed earlier | Later checks still run (dependency is for ordering, not gating — gating is done via `Condition` + `Sequence` explicitly) |
| Missing check spec for module | Falls back to `ModuleAdapter` transparently |
| Check tree for non-registered module | Falls back to `ModuleAdapter` |

## Testing Strategy

### New test files (~25 tests)

| File | Tests |
|------|-------|
| `test_bt_check_adapter.py` | CheckAdapter wraps check_fn, adds result to blackboard, returns SUCCESS on PASS, FAILURE on FAIL, handles exceptions |
| `test_bt_builder.py` | CheckSpec creation, dependency grouping (no deps → one group, chain deps → sequential groups), build_module produces correct tree structure, fallback to ModuleAdapter for unregistered modules |
| `test_bt_checks_headers.py` | Headers check tree: all PASS, one FAIL, one ERROR, discovery failure propagation |
| `test_bt_checks_auth.py` | Auth check tree: form found → all checks run, no form → discovery fails, check ordering respects depends_on |

### Existing tests unchanged

All 184 existing tests continue to pass. The new code is purely additive — `ModuleAdapter`, `Sequence`, `Selector`, `Parallel`, decorators, and all module `test()` methods remain untouched.

## Growth Summary

| Metric | Before | After |
|--------|--------|-------|
| Engine node types | 10 | 13 (+CheckAdapter, DiscoverAction, CheckTreeBuilder) |
| Engine files | 4 | 6 (+builder.py, registry.py) |
| Module check specs | 0 | 3 modules (headers, auth, cors) |
| Test count | 184 | ~209 |
| Tree inspectability | Module-level opaque | Check-level transparent |

## What This Enables Next

Once check-level BTs are in place, **Attack Chain Trees** (Direction 2) become natural:

```python
Sequence("csrf_to_xss_chain", children=[
    CheckAdapter("csrf_scan", check_csrf_vulnerability),
    Condition("csrf_found?", lambda bb: bb.get("csrf_found", False)),
    Retry("xss_via_csrf", max_attempts=3,
          child=CheckAdapter("xss_exploit", check_xss_via_csrf)),
])
```

Each individual check is a BT node — they compose with all existing decorators and composites.

## Open Questions

- **Single-request optimization:** Currently if 8 header checks run in parallel, they each make their own HTTP request. Should `DiscoverAction` cache the response on the blackboard? **Decision:** Yes, `DiscoverAction` stores `(endpoint, response)` pairs so check functions can read cached responses instead of re-requesting.
- **ModuleAdapter → CheckAdapter migration scope:** Should we migrate all 10 modules in one pass? **Decision:** Migrate headers, auth, and CORS as reference implementations. Remaining 7 modules migrate incrementally in follow-up work.
- **Check function signature:** Should check functions receive the `Blackboard` or just `(client, target, endpoints, cached_responses)`? **Decision:** Receiving the full `Blackboard` is more flexible — they can read/write shared state, which is essential for attack chains.
