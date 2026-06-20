# Plugin System Design — Easy Modding for Many Systems

**Date:** 2026-06-20
**Status:** Draft

## Problem Statement

Adding a new module to WebSec Test currently requires editing **5 separate locations** in `main.py` (import, ALL_MODULES, MODULE_FACTORIES, CHECK_SPEC_REGISTRY, argparse choices). Third-party modules are impossible without forking the repo. Additionally, the system is deeply coupled to HTTP web targets — every module assumes `SessionClient`, a URL target, and HTTP responses. Supporting other scan types (cloud APIs, databases, mobile backends, file systems) would require architectural changes.

## Constraints

- Existing modules must continue working with **zero changes** to their class implementation
- The behavior tree engine must remain the execution mechanism
- CLI behavior (`--modules`, `--check`, `--discover`, etc.) must be preserved
- No breaking changes to the existing test suite
- Must support both first-party (built-in) and third-party (pip-installable) modules

## Approach

### Two-Tier Plugin Architecture

1. **Tier 1 — Decorator auto-registry** for first-party modules. A `@register_module` decorator on the class is the only registration step needed. No edits to `main.py`.

2. **Tier 2 — Python entry points** for third-party pip-distributed plugins. Modules installed as packages via `pip` are auto-discovered through `importlib.metadata.entry_points`.

This mirrors how pytest, flake8, and pylint handle plugins — proven, Pythonic, minimal ceremony.

### Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Registration mechanism | Decorators | Self-declaring modules. No separate config to keep in sync |
| Target coupling | `TargetProtocol` ABC | Decouples modules from HTTP. Same module interface for web, cloud, DB targets |
| Module categorization | String `category` field | Enables `--category web` filtering, organizes unrelated scan types |
| Central registry | Singleton `ModuleRegistry` | Single source of truth — `main.py` reads from it, never hardcodes |
| Entry point group | `websec_test.modules` | Matches Python packaging convention for plugin discovery |

## Architecture

```
websec_test/
├── main.py                       # Reads from registry, never hardcodes
├── plugins/                      # NEW: Plugin infrastructure
│   ├── __init__.py
│   ├── protocol.py               # ModuleProtocol, TargetProtocol ABCs
│   ├── decorators.py             # @register_module, @register_category
│   ├── registry.py               # ModuleRegistry singleton
│   └── loader.py                 # discover_modules(), discover_entry_points()
├── modules/                      # Built-in modules (unchanged structure)
│   ├── headers.py                # + @register_module decorator
│   ├── auth.py                   # + @register_module decorator
│   └── ...                       # All 10 existing modules get decorator
```

## Components

### 1. `plugins/protocol.py` — Module Contracts

Three interfaces, progressively richer:

```python
class ModuleProtocol(Protocol):
    """Minimal contract every module must satisfy."""
    name: str                                 # "headers", "auth"
    category: str                             # "web-security", "sast", "database"
    description: str                          # One-liner for CLI help

    def discover(self, context) -> list[Endpoint]: ...
    def test(self, context, endpoints) -> list[TestResult]: ...


class TargetProtocol(Protocol):
    """What a module sees — not HTTP-specific."""
    def request(self, req: Request) -> Response: ...
    @property
    def base_url(self) -> str: ...


class HasCheckSpecs(Protocol):
    """Optional: per-check breakdown for --check-level."""
    def check_specs(self) -> list[CheckSpec]: ...
```

The `context` object replaces the old `(client, target)` tuple. For HTTP modules, it carries `SessionClient` + URL. For SAST modules, it carries a `Path`. For database modules, it carries a DB connection.

### 2. `plugins/decorators.py` — Self-Registration

```python
def register_module(name=None, category="web-security"):
    """Decorator that registers a module class into the central registry.
    
    Args:
        name: Module name (default: lowercase of class name minus 'Module')
        category: Module category for CLI filtering
    """
    def wrapper(cls):
        module_name = name or cls.__name__.replace("Module", "").lower()
        registry.register(
            cls=cls,
            name=module_name,
            category=category,
            check_specs_fn=cls.check_specs if hasattr(cls, "check_specs") else None,
        )
        return cls
    return wrapper
```

Usage in a module file:
```python
@register_module(category="web-security")
class HeadersModule:
    name = "headers"
    description = "Check for missing security headers"
    ...
```

### 3. `plugins/registry.py` — Single Source of Truth

```python
class ModuleRegistry:
    """Central registry for all modules. Populated by decorators and loader."""
    
    def __init__(self):
        self._modules: dict[str, type] = {}
        self._check_specs: dict[str, Callable] = {}
        self._categories: dict[str, list[str]] = {}
        self._descriptions: dict[str, str] = {}
    
    def register(self, cls, name, category, check_specs_fn=None):
        self._modules[name] = cls
        self._categories.setdefault(category, []).append(name)
        self._descriptions[name] = getattr(cls, "description", "")
        if check_specs_fn:
            self._check_specs[name] = check_specs_fn
    
    @property
    def all_modules(self) -> list[str]:
        return list(self._modules.keys())
    
    def by_category(self, category: str) -> list[str]:
        return self._categories.get(category, [])
    
    def get_check_specs(self, name: str) -> list[CheckSpec]:
        fn = self._check_specs.get(name)
        return fn() if fn else []
    
    def instantiate(self, name: str, **kwargs):
        cls = self._modules.get(name)
        if not cls:
            raise KeyError(f"Unknown module: {name}")
        return cls(**kwargs)
    
    @property
    def categories(self) -> dict[str, list[str]]:
        return dict(self._categories)

# Global singleton
registry = ModuleRegistry()
```

### 4. `plugins/loader.py` — Auto-Discovery

```python
def discover_first_party():
    """Trigger import of all built-in modules so decorators fire."""
    import websec_test.modules  # __init__.py loads all module files
    
    # Alternative: programmatic scan
    import pkgutil
    import websec_test.modules as pkg
    for importer, modname, ispkg in pkgutil.iter_modules(pkg.__path__):
        if not modname.startswith("_"):
            __import__(f"websec_test.modules.{modname}")


def discover_entry_points():
    """Discover third-party plugins via Python entry_points."""
    if sys.version_info >= (3, 10):
        from importlib.metadata import entry_points
        eps = entry_points(group="websec_test.modules")
        for ep in eps:
            try:
                cls = ep.load()
                registry.register(cls, ...)
            except Exception as e:
                import logging
                logging.warning(f"Failed to load plugin {ep.name}: {e}")


def discover_all():
    """Run all discovery strategies."""
    discover_first_party()
    discover_entry_points()
```

### 5. `main.py` — What Changes

**Before:** 30 lines of hardcoded imports + 4 parallel registries
**After:**

```python
from websec_test.plugins.loader import discover_all
from websec_test.plugins.registry import registry

# Auto-discover ALL modules (first-party + third-party)
discover_all()

# Dynamic registration from registry
ALL_MODULES = registry.all_modules
CHECK_SPEC_REGISTRY = {name: registry.get_check_specs(name) for name in ALL_MODULES}

# argparse choices become dynamic
parser.add_argument("--modules", nargs="+", choices=ALL_MODULES, ...)
parser.add_argument("--category", choices=list(registry.categories.keys()),
                    help="Run only modules in this category")
```

## Data Flow

```
CLI starts → parse_args()
    ↓
discover_all() → imports websec_test.modules
    → each @register_module fires → registry.populate()
    → entry_points() loads 3rd-party plugins → registry.populate()
    ↓
ALL_MODULES = registry.all_modules  (dynamic)
    ↓
User specifies --modules or --all or --category
    ↓
registry.instantiate(name, **kwargs) → module instance
    ↓
ModuleAdapter wraps instance → BT engine executes
    ↓
Results collected, reported (unchanged)
```

## Adding a New Module: Comparison

| Step | Before | After |
|---|---|---|
| Create file | `modules/x.py` | `modules/x.py` |
| Implement class | `class XModule: ...` | `class XModule: ...` |
| Register it | Edit 5 places in main.py | Add `@register_module` decorator |
| Add check_specs | Import + add to CHECK_SPEC_REGISTRY | Implement `check_specs()` classmethod |
| Third-party? | Impossible | pip install → auto-discovered |
| CLI picks it up? | No, must update choices | Yes, auto-populated |
| Works with --check-level? | Add to CHECK_LEVEL_MODULES | Auto-detected if check_specs exists |

## Category System

The `category` field enables organizing modules by target system, which supports targeted CLI flags:

| Category | Example Modules | Context Type |
|---|---|---|
| `web-security` | headers, auth, csrf, injection | SessionClient + URL |
| `sast` | scanner, assessor, checker | File system path |
| `database` | mongodb-check | DB connection config |
| `cloud` | s3-bucket-audit, iam-check | Cloud SDK client |
| `api` | graphql-audit, rest-fuzzer | HTTP API client |
| `mobile` | android-deeplink, ios-pinning | Mobile proxy config |

Each category has a recommended `TargetProtocol` implementation, but modules remain decoupled from the concrete transport.

## Error Handling

| Scenario | Behavior |
|---|---|
| Broken module file | `discover_first_party()` catches import error, logs warning, continues |
| Plugin raises on load | `discover_entry_points()` catches, logs, skips |
| Duplicate module name | Last-registered wins with warning |
| Missing check_specs | Module works fine; `--check-level` falls back to ModuleAdapter |
| Empty category | CLI filter returns empty, exits gracefully |

## Testing Strategy

| Layer | What | How |
|---|---|---|
| Unit | Registry CRUD | Test singleton: register, lookup, instantiate |
| Unit | Decorator | `@register_module` on dummy class, assert registry populated |
| Integration | Auto-discovery | `discover_all()` finds all 10 built-in modules |
| Integration | Entry points | Mock `importlib.metadata.entry_points`, verify loading |
| Migration | Backward compat | Existing 252 tests pass with no changes |
| CLI | Dynamic choices | `parse_args()` choices match `registry.all_modules` |

## Migration Path

**Phase 1:** Create `plugins/` package (protocol, decorators, registry). Existing code unchanged.

**Phase 2:** Add `@register_module` to each existing module. `main.py` still uses hardcoded dicts (parallel run).

**Phase 3:** Wire `main.py` to read from registry. Remove hardcoded `ALL_MODULES`, `MODULE_FACTORIES`, `CHECK_SPEC_REGISTRY`. All 252 tests must still pass.

**Phase 4:** Add `loader.py` with auto-discovery. Remove explicit imports from `main.py`.

**Phase 5:** Document plugin authoring guide. Add entry_point support.

**Phase 6 (optional):** Add `TargetProtocol` for non-HTTP systems.

## Open Questions

- Should the `category` field be an enum or freeform string? (Leaning toward freeform with documented conventions)
- How do we handle the `auth` module's special construction (`AuthModule(credentials=..., target=...)`)? Proposing a `create()` classmethod convention.
- Should we keep `CHECK_LEVEL_MODULES` set or derive it from which modules have check_specs? (Deriving is simpler)
