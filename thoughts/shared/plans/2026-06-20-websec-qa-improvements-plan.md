# Implementation Plan: WebSec QA Improvements

## Overview

6 prioritized fixes from the QA review, ordered P0 → P2. All are refactoring changes — no behavioral changes, all 244 tests must pass.

---

## 1. P0 — Thread leak in Timeout decorator

**File:** `websec_test/engine/decorators.py`

**Problem:** `Timeout.tick()` creates a `ThreadPoolExecutor(max_workers=1)` on every invocation without calling `.shutdown()`, leaking threads.

**Fix:** Replace per-tick executor creation with a persistent executor stored as an instance variable. Add a `__del__` or context manager cleanup path.

**Changes:**
- Add `self._executor = ThreadPoolExecutor(max_workers=1)` in `__init__`
- In `tick()`: replace `with ThreadPoolExecutor(max_workers=1) as executor` with `self._executor.submit()`
- Add `__del__` that calls `self._executor.shutdown(wait=False)`
- Add `__enter__`/`__exit__` for context manager support

**Verification:** `pytest tests/test_bt_decorators.py::test_timeout` passes

---

## 2. P0 — Document Parallel concurrency semantics

**File:** `websec_test/engine/nodes.py`

**Problem:** `Parallel.tick()` iterates children sequentially but the class name/doc imply concurrent execution.

**Fix:** Update the docstring on `Parallel` class and `tick()` method to clarify:
- Children are run sequentially in the current implementation
- `min_success` is the count of successful children required for overall SUCCESS
- Future work: could be swapped to `ThreadPoolExecutor` for I/O-bound checks

**No code logic change** — only docstrings.

**Verification:** `pytest tests/test_bt_nodes.py` passes

---

## 3. P1 — Coverage configuration

**File:** `pyproject.toml`

**Problem:** No pytest or coverage config. Can't measure coverage.

**Fix:** Add `[tool.pytest.ini_options]` and `[tool.coverage]` sections:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
minversion = "7.0"
log_cli = true

[tool.coverage.run]
source = ["websec_test"]
omit = ["*/tests/*", "*/__init__.py"]

[tool.coverage.report]
fail_under = 0  # informational for now
show_missing = true
```

**Verification:** `pytest tests/ --cov=websec_test` runs successfully

---

## 4. P1 — Module registry in main.py

**File:** `websec_test/main.py` (lines 50–110)

**Problem:** 10-branch if-else chain mapping module names to deferred imports + instantiation. Brittle, requires touching 3 places to add a module.

**Fix:** Replace with a dict-based module registry at module level:

```python
MODULE_REGISTRY = {
    "headers": lambda: HeadersModule,
    "auth": lambda: AuthModule,
    "csrf": lambda: CSRFModule,
    "injection": lambda: InjectionModule,
    "authz": lambda: AuthzModule,
    "ssl_tls": lambda: SSLTLSModule,
    "cors": lambda: CORSModule,
    "cookies": lambda: CookiesModule,
    "disclosure": lambda: DisclosureModule,
    "methods": lambda: MethodsModule,
}
```

Then in `main()`:
```python
if module_name not in MODULE_REGISTRY:
    logging.warning("Unknown module: %s", module_name)
    continue
module_class = MODULE_REGISTRY[module_name]()
module = module_class(...)
```

Imports move to top of file (or keep lazy via the lambda — but simpler to just import all top-level since they're all always available).

**Simpler approach:** Import all modules at top of file, use a dict mapping names to classes directly (the lazy imports were over-engineering for a CLI tool that loads all modules anyway).

**Verification:** `pytest tests/test_main.py` + all BT integration tests

---

## 5. P2 — Deduplicate form extraction

**File:** `websec_test/modules/injection.py`

**Problem:** Two copies of `_extract_form_inputs` logic:
- Lines 18-33: `async` context method returning `namedtuple`
- Lines 279-296: standalone function returning dict

**Fix:** Extract shared logic into a module-level function. Both callers use the shared function. Standardize return type to dict.

**Changes:**
1. Create shared function `_parse_form_inputs(html: str) -> list[dict]` that extracts input names/values from HTML form
2. Replace `InjectionModule._extract_form_inputs` body with call to shared function, adapt result format
3. Replace standalone `_extract_form_inputs` body with call to shared function

**Verification:** `pytest tests/test_injection.py` passes

---

## 6. P2 — Clean up stale root-level files

**Files:** Delete `_check_remaining.py` from project root. Add `_*.py` to `.gitignore`.

**Changes:**
1. `Remove-Item -LiteralPath "_check_remaining.py"`
2. Append `_*.py` line to `.gitignore`

**Verification:** `dir _.py` returns empty

---

## Execution Order

```
1. Clean up stale files + .gitignore     (safe, no deps)
2. Document Parallel docstrings           (safe, no deps)
3. Thread leak fix                        (safe, no deps)
4. Deduplicate form extraction            (safe, no deps)
5. Coverage config                       (safe, no deps)
6. Module registry                       (last, most risky)
```

Run `pytest tests/ -v` after all changes.
