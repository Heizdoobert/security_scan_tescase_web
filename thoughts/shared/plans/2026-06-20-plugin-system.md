# Plugin System Implementation Plan

**Date:** 2026-06-20
**Design:** `thoughts/shared/designs/2026-06-20-plugin-system-design.md`
**Constraint:** All 252 existing `pytest tests/ -v` tests must pass at every phase

---

## Phase 1 — Plugin Infrastructure (No-Op to Existing Code)

**Goal:** Create `websec_test/plugins/` package with registry, decorators, and protocol. Nothing changes in existing code — all 252 tests pass unchanged.

### Files to create:

**1. `websec_test/plugins/__init__.py`**
- Public exports: `ModuleRegistry`, `registry`, `register_module`, `ModuleProtocol`, `TargetProtocol`

**2. `websec_test/plugins/protocol.py`**
- Define `ModuleProtocol` (Protocol class with `name`, `description`, `category`, `discover()`, `test()`)
- Define `TargetProtocol` (Protocol class with `request()`, `base_url`)
- Define `HasCheckSpecs` (Protocol with `check_specs()`)
- These are structural typing protocols — no metaclass, no inheritance requirement

**3. `websec_test/plugins/registry.py`**
- `ModuleRegistry` singleton class with:
  - `_modules: dict[str, type]` — module name → class
  - `_categories: dict[str, list[str]]` — category → [module names]
  - `_descriptions: dict[str, str]` — module name → description string
  - `_check_specs_fns: dict[str, Callable]` — optional check_specs factory per module
  - `register(cls, name, category, check_specs_fn=None)` — registers a module
  - `all_modules` property — returns list of all registered names
  - `by_category(category)` — filter modules by category string
  - `categories` property — dict of all category → module lists
  - `get_check_specs(name)` — calls the stored factory, returns list or `[]`
  - `instantiate(name, **kwargs)` — returns `cls(**kwargs)` or raises `KeyError`
- Module-level singleton `registry = ModuleRegistry()`
- Duplicate name: last-registered wins, emit warning via `logging.warning`

**4. `websec_test/plugins/decorators.py`**
- `register_module(name=None, category="web-security")` — decorator factory
  - If `name` is None, derive from class name: `cls.__name__.replace("Module", "").lower()`
  - Calls `registry.register(cls=cls, name=module_name, category=category, check_specs_fn=...)`
  - Detects `check_specs` attribute (classmethod or static method) for auto-detection of check-level support
  - Returns the class unchanged (pure registration, no wrapping)

**5. `websec_test/plugins/loader.py`** (stub for now)
- Define `discover_first_party()` — placeholder that logs "not yet active"
- Define `discover_entry_points()` — placeholder that logs "not yet active"
- Define `discover_all()` — calls both placeholders

### Verify:
```bash
pytest tests/ -v
# Expected: 252 passed, 0 failed
# Manual: import websec_test.plugins, assert registry.all_modules == []
```

### Dependencies: None

---

## Phase 2 — Add `@register_module` to All 10 Modules (Dual-Run Mode)

**Goal:** Add `@register_module` decorator to every existing module class. `main.py` still uses hardcoded dicts — no behavior change. Registry populates in parallel for validation.

### Files to modify (10 files, same pattern each):

**1. `websec_test/modules/headers.py`**
- Add import: `from websec_test.plugins import register_module`
- Add `@register_module(category="web-security")` above `class HeadersModule`
- Add class attribute: `description = "Check for missing security headers"` (or similar, must be a string)

**2. `websec_test/modules/auth.py`**
- Same pattern: `@register_module(category="web-security")` above `class AuthModule`
- `AuthModule.__init__` takes `(self, credentials=None, target="")` — the `instantiate` method already passes `**kwargs`, but this requires explicit handling in Phase 3's `_make_module` replacement
- Add `description` attribute

**3. `websec_test/modules/csrf.py`**
- Same pattern, category `"web-security"`, add `description`

**4. `websec_test/modules/injection.py`**
- Same pattern, category `"web-security"`, add `description`

**5. `websec_test/modules/authz.py`**
- Same pattern, category `"web-security"`, add `description`

**6. `websec_test/modules/ssl_tls.py`**
- Same pattern, category `"web-security"`, add `description`

**7. `websec_test/modules/cors.py`**
- Same pattern, category `"web-security"`, add `description`

**8. `websec_test/modules/cookies.py`**
- Same pattern, category `"web-security"`, add `description`

**9. `websec_test/modules/disclosure.py`**
- Same pattern, category `"web-security"`, add `description`

**10. `websec_test/modules/methods.py`**
- Same pattern, category `"web-security"`, add `description`

**11. `websec_test/modules/__init__.py`** (modify)
- Add imports for all 10 modules so their decorators fire on import:
  ```python
  from websec_test.modules import headers, auth, csrf, injection, authz, ssl_tls, cors, cookies, disclosure, methods
  ```
  Alternatively: make it a lazy-load using `__getattr__` (Python 3.7+) for auto-import on access. But simple explicit imports are safer and more debuggable.

### Verify:
```bash
pytest tests/ -v
# Expected: 252 passed
# Manual verification: python -c "from websec_test.plugins.loader import discover_first_party; discover_first_party(); from websec_test.plugins.registry import registry; print(registry.all_modules)"
# Should show all 10 module names
```

### Dependencies: Phase 1 must be done first

---

## Phase 3 — Wire `main.py` to Read from Registry (Remove Hardcoded Dicts)

**Goal:** Replace `ALL_MODULES`, `MODULE_FACTORIES`, `CHECK_SPEC_REGISTRY`, `CHECK_LEVEL_MODULES` with dynamic reads from `registry`. Remove all per-module imports from the top of `main.py`.

### Files to modify:

**1. `websec_test/main.py`** — Major refactor

- **Remove** all 10 explicit module imports (lines 13-22):
  ```python
  from websec_test.modules.headers import HeadersModule, headers_check_specs
  from websec_test.modules.auth import AuthModule, auth_check_specs
  # ... all 10
  ```

- **Replace** `ALL_MODULES` (line 24-25) with:
  ```python
  from websec_test.plugins.registry import registry
  # ALL_MODULES is now registry.all_modules
  ```
  But keep a local `ALL_MODULES = registry.all_modules` for backward compat with `parse_args`.

- **Replace** `MODULE_FACTORIES` (lines 30-40) — remove the dict. The `_make_module` closure becomes:
  ```python
  def _make_module(name: str) -> object:
      return registry.instantiate(name)
  ```
  But `auth` module is special: `AuthModule(credentials=args.auth, target=target)`. Handle via:
  ```python
  def _make_module(name: str) -> object:
      if name == "auth":
          return AuthModule(credentials=args.auth, target=target)
      return registry.instantiate(name)
  ```
  Still need to import `AuthModule` for this special case. Alternative: add a `create()` classmethod pattern to `AuthModule` — but keep the explicit import for now (fewer changes, test-safe).

- **Replace** `CHECK_SPEC_REGISTRY` (lines 41-52) with dynamic:
  ```python
  CHECK_SPEC_REGISTRY = {name: registry.get_check_specs(name) for name in ALL_MODULES}
  ```
  This requires that the registry learns how to call `check_specs()`. Update `registry.register()` to detect `check_specs` as a class method/function on the class:
  ```python
  check_specs_fn = getattr(cls, 'check_specs', None)
  ```
  Wait — looking at the existing modules: `headers_check_specs()` is a **module-level function** decorated with `@register("headers")`, NOT a classmethod. The engine registry (`check_registry`) already stores these. So `main.py` should read from `check_registry` directly, not from the module registry:

  ```python
  from websec_test.engine.registry import check_registry
  CHECK_SPEC_REGISTRY = {name: fn() for name, fn in check_registry.items()}
  ```

  This means the plugin registry doesn't need to duplicate check_specs storage. The engine registry already has it.

- **Replace** `CHECK_LEVEL_MODULES` (lines 27-28):
  ```python
  CHECK_LEVEL_MODULES = set(check_registry.keys())
  ```
  Derived automatically.

- **Keep** the `AuthModule` import for the special factory case:
  ```python
  from websec_test.modules.auth import AuthModule
  ```

- **Remove** all other per-module imports.

- `parse_args` choices stay the same: `choices=ALL_MODULES` but now ALL_MODULES is `registry.all_modules`.

### Key design decision:
The existing `engine/registry.py` already has a `check_registry` populated by `@register("module_name")` decorators. The check-level data lives there. The new `plugins/registry.py` owns **module-level** data (class, category, description, instantiation). These are orthogonal concerns and should not be merged.

### Files to verify no changes needed:
- `websec_test/engine/__init__.py` — no change
- `websec_test/engine/registry.py` — no change (still the check-level registry)
- All `tests/test_*.py` — no change expected

### Verify:
```bash
pytest tests/ -v
# Expected: 252 passed
# If tests reference main.py internals like MODULE_FACTORIES or ALL_MODULES, update those references
```

### Potential test impacts:
- `test_main.py:51-53` — `test_parse_args_all_modules` asserts `args.modules == [hardcoded list]`. This must still match `registry.all_modules`. Change the test to compare against `sorted(registry.all_modules)` or keep the hardcoded list. **Keep hardcoded** in the test for safety — the list won't change.
- Any test that imports `MODULE_FACTORIES` or `CHECK_SPEC_REGISTRY` directly from main will break. Grep for these. If found, the test should import from registry instead.

### Dependencies: Phase 1 + 2

---

## Phase 4 — Auto-Discovery via `loader.py` + Programmatic Module Scan

**Goal:** Replace explicit `from websec_test.modules import X` in `main.py` with `discover_all()` that imports all modules programmatically. Eliminate remaining per-module references.

### Files to modify:

**1. `websec_test/plugins/loader.py`** — Replace stubs with real logic
- `discover_first_party()`:
  ```python
  import pkgutil
  import websec_test.modules as pkg
  for importer, modname, ispkg in pkgutil.iter_modules(pkg.__path__):
      if not modname.startswith("_"):
          __import__(f"websec_test.modules.{modname}")
  ```
  This triggers each module's `@register_module` decorator on import.
- `discover_entry_points()`:
  ```python
  import sys
  if sys.version_info >= (3, 10):
      from importlib.metadata import entry_points
      eps = entry_points(group="websec_test.modules")
      for ep in eps:
          try:
              cls = ep.load()
              registry.register(cls=cls, name=ep.name, category="web-security")
          except Exception as e:
              logging.warning(f"Failed to load plugin '{ep.name}': {e}")
  ```
- `discover_all()`: calls both, wrapped in try/except with logging

**2. `websec_test/modules/__init__.py`** — Revert or keep
- The explicit imports from Phase 2 are now redundant since `loader.py` does programmatic scan. Keep them as a safety net (explicit > implicit), or remove them now that `loader.py` handles it.
- **Decision:** Keep them. They provide clear dependency visibility and IDE support. The programmatic scan is a fallback/complementary mechanism.

**3. `websec_test/main.py`** — Refactor to use `discover_all()`
- At module level, replace:
  ```python
  from websec_test.plugins.registry import registry
  from websec_test.plugins.loader import discover_all
  # Import engine registry for check-level specs
  from websec_test.engine.registry import check_registry as engine_check_registry
  
  # Auto-discover ALL modules
  discover_all()
  
  # Dynamic registries
  ALL_MODULES = registry.all_modules
  CHECK_SPEC_REGISTRY = {name: fn() for name, fn in engine_check_registry.items()}
  CHECK_LEVEL_MODULES = set(engine_check_registry.keys())
  ```

- The `AuthModule` special case in `_make_module` needs the class. Instead of a direct import, use:
  ```python
  def _make_module(name: str) -> object:
      if name == "auth" and args.auth:
          return registry.instantiate(name, credentials=args.auth, target=target)
      return registry.instantiate(name)
  ```
  This requires `AuthModule.__init__` to accept `**kwargs` and pop what it needs. Verify that `AuthModule.__init__(self, credentials=None, target="")` already handles this with `**kwargs`. If not, adjust:

  In `websec_test/modules/auth.py`:
  ```python
  def __init__(self, credentials=None, target="", **kwargs):
      self.credentials = credentials
      self.target = target
  ```
  Add `**kwargs` to swallow extra params.

- Remove the `from websec_test.modules.auth import AuthModule` import entirely.

- `run_discover()` currently reads `CHECK_SPEC_REGISTRY` — no change needed since it's still a module-level dict.

### Edge cases for `discover_first_party()`:
- If a module file has a syntax error, `__import__` raises `SyntaxError`. Wrap in try/except, log warning, continue.
- If `websec_test.modules.__path__` doesn't exist (unlikely), handle `TypeError`.
- If a module's `@register_module` fires but the class has no `discover`/`test` methods, the registry still stores it — `ModuleAdapter` will fail at runtime. This is acceptable (user error, not framework error).

### Verify:
```bash
pytest tests/ -v
# Expected: 252 passed
# Manual: python -c "from websec_test.plugins.loader import discover_all; discover_all(); from websec_test.plugins.registry import registry; print(registry.all_modules)"
```

### Dependencies: Phase 3

---

## Phase 5 — Entry Point Support + Plugin Authoring Guide

**Goal:** Enable third-party plugins via `pip install` + entry point discovery. Document the process.

### Files to create:

**1. `docs/superpowers/plugin-authoring-guide.md`** (or similar)
- How to create a pip-installable plugin package
- Required `pyproject.toml` with `[project.entry-points."websec_test.modules"]`
- Example plugin structure:
  ```
  my-plugin/
  ├── pyproject.toml
  └── src/
      └── my_plugin/
          ├── __init__.py
          └── scanner.py
  ```
- `pyproject.toml` entry:
  ```toml
  [project.entry-points."websec_test.modules"]
  my-scanner = "my_plugin.scanner:MyScannerModule"
  ```
- Module class contract (from `protocol.py`)
- Category conventions (documented values: `web-security`, `sast`, `database`, `cloud`, `api`, `mobile`)
- How to test locally with `pip install -e .`
- Example: full working plugin with `@register_module` inside the package

**2. `tests/test_plugin_loader.py`** (NEW)
- Unit test: mock `importlib.metadata.entry_points` to return a dummy entry, verify `discover_entry_points()` calls `registry.register()`
- Unit test: broken entry point is caught and logged, doesn't crash
- Integration test: `discover_all()` returns all 10 built-in modules (no entry points mocked)
- Error test: `discover_first_party()` with a broken module file logs warning

### Files to modify:

**1. `websec_test/plugins/loader.py`** — Finalize `discover_entry_points()`
- Add proper error handling for:
  - Module not found (`ModuleNotFoundError`)
  - Import error inside plugin (`ImportError`)
  - Attribute error (entry point doesn't point to a class)
  - Class doesn't conform to ModuleProtocol
- Add logging statements at `INFO` level for each discovered plugin
- Add `__all__` exports

**2. `websec_test/plugins/__init__.py`** — Add `"discover_all"` to exports

### Verify:
```bash
pytest tests/ -v
# Expected: 252 + new tests all passing
# Manual: pip install a test plugin, verify it appears in registry.all_modules
```

### Dependencies: Phase 4

---

## Phase 6 (Optional) — `TargetProtocol` for Non-HTTP Systems

**Goal:** Decouple modules from HTTP by introducing `TargetProtocol` as the abstract interface modules see. This is a deeper refactoring — can be deferred.

### Files to modify:

**1. `websec_test/plugins/protocol.py`** — Already defined `TargetProtocol`
- No changes needed if the ABC was designed correctly in Phase 1

**2. `websec_test/plugins/protocol.py`** — Add `Context` dataclass
- Replace the old `(client, target)` tuple with a `ScanContext` object:
  ```python
  @dataclass
  class ScanContext:
      target_impl: TargetProtocol
      target_url: str = ""
      credentials: str | None = None
      timeout: int = 10
      extra: dict = field(default_factory=dict)
  ```
- Web modules get `HttpTarget(client=SessionClient(...), base_url=...)`
- SAST modules get `FileSystemTarget(path=...)`
- DB modules get `DatabaseTarget(connection_string=...)`

**3. `websec_test/plugins/protocol.py`** — HTTP implementation
- `HttpTarget(TargetProtocol)` wrapping `SessionClient`:
  ```python
  class HttpTarget:
      def __init__(self, client: SessionClient, base_url: str):
          self._client = client
          self._base_url = base_url
      
      def request(self, req: Request) -> Response:
          ...
      
      @property
      def base_url(self) -> str:
          return self._base_url
  ```

**4. `websec_test/main.py`** — Build `HttpTarget` instead of passing raw `(client, target)`
- Replace `blackboard = Blackboard(client=client, target=target)` with:
  ```python
  target_impl = HttpTarget(client, target)
  blackboard = Blackboard(target=target_impl)
  ```
- Update `ModuleAdapter` to extract `client` and `target` from the target for backward compat
- OR: update all modules to accept `ScanContext` instead of `(client, target)` — **breaking change**, skip for now

**5. `websec_test/engine/adapters.py`** — Update `ModuleAdapter`
- If the wrapped module expects `(client, target)`, extract from target impl
- If the module accepts `ScanContext`, pass it directly
- This is a bridge layer to avoid breaking existing modules

**Decision:** Keep `(client, target)` as the default calling convention. `TargetProtocol` is the interface for NEW modules. Old modules work via ModuleAdapter's extraction logic.

### Verify:
```bash
pytest tests/ -v
# Expected: 252 passed
# Manual: create a non-HTTP module (e.g., file-system scanner) that inherits from both ModuleProtocol and a non-HTTP TargetProtocol
```

### Dependencies: Phase 5 (conceptually; can be done independently)

---

## Summary of New Files

| File | Phase | Purpose |
|---|---|---|
| `websec_test/plugins/__init__.py` | 1 | Package init, exports |
| `websec_test/plugins/protocol.py` | 1 | ModuleProtocol, TargetProtocol, HasCheckSpecs |
| `websec_test/plugins/registry.py` | 1 | ModuleRegistry singleton |
| `websec_test/plugins/decorators.py` | 1 | @register_module decorator |
| `websec_test/plugins/loader.py` | 1 (stub), 4 (real) | discover_first_party, discover_entry_points |
| `tests/test_plugin_loader.py` | 5 | Plugin loader tests |
| `docs/superpowers/plugin-authoring-guide.md` | 5 | Third-party plugin docs |

## Summary of Modified Files

| File | Phase | What Changes |
|---|---|---|
| `websec_test/modules/__init__.py` | 2 | Add explicit imports of all 10 modules |
| `websec_test/modules/*.py` (10 files) | 2 | Add `@register_module` decorator + `description` attribute |
| `websec_test/main.py` | 3, 4 | Remove hardcoded registries, use `registry` + `check_registry` |
| `websec_test/modules/auth.py` | 4 | Add `**kwargs` to `__init__` for generic instantiation |

## Files That Should NOT Change

| File | Reason |
|---|---|
| `websec_test/engine/*.py` | Engine is orthogonal to registration |
| `websec_test/results/*.py` | Results models unchanged |
| `websec_test/client/*.py` | SessionClient unchanged |
| `websec_test/security/*.py` | SecOps toolkit unchanged |
| `websec_test/config/*.py` | Payloads unchanged |
| `websec_test/mongodb_check.py` | Standalone script, unrelated |
| `tests/test_*.py` (most) | Only new test_plugin_loader.py added |

## Verification Command (Every Phase)

```bash
cd D:\testcase_web
pytest tests/ -v --tb=short 2>&1 | tail -5
```

Expected output after every phase:
```
tests/test_xxx.py ..........                                       [100%]
========================= 252 passed in X.XXs =========================
```

## Rollback Strategy

If a phase breaks tests:
1. `git diff` to see what changed
2. If the change is in `main.py`, check that `ALL_MODULES` / `MODULE_FACTORIES` / `CHECK_SPEC_REGISTRY` / `CHECK_LEVEL_MODULES` still resolve correctly
3. If the change is in a module file, verify the `@register_module` decorator doesn't interfere with class instantiation
4. Run `python -c "from websec_test.modules.headers import HeadersModule; m = HeadersModule(); assert m.discover"` to verify module load
