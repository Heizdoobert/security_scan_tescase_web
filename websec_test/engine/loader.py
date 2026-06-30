"""Plugin loader — auto-discovers security modules from websec_test/modules/.

Eliminates the need to manually register new modules in main.py.
Convention: every .py file in modules/ (except __init__.py) is a module.
"""
import importlib
import inspect
import pkgutil
import sys
from pathlib import Path

from .builder import CheckSpec
from .registry import check_registry


def discover_modules():
    """Scan websec_test.modules for module classes and their check specs.

    Returns:
        module_names: list[str] — sorted module names
        module_factories: dict[str, type] — name → class
        check_spec_registry: dict[str, list[CheckSpec]] — name → specs
    """
    import websec_test.modules as pkg

    module_names = []
    module_factories = {}
    check_spec_registry = {}

    for importer, modname, ispkg in pkgutil.iter_modules(pkg.__path__):
        if modname.startswith("_") or ispkg:
            continue

        try:
            mod = importlib.import_module(f"websec_test.modules.{modname}")
        except Exception as e:
            print(f"[!] Failed to load module '{modname}': {e}")
            continue

        # Find module class: any class with both discover() and test() methods
        module_class = None
        for name, obj in inspect.getmembers(mod, inspect.isclass):
            if name == modname.capitalize() + "Module":
                module_class = obj
                break
        if module_class is None:
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if hasattr(obj, "discover") and hasattr(obj, "test"):
                    module_class = obj
                    break
        if module_class is None:
            continue

        module_names.append(modname)
        module_factories[modname] = module_class

        # Get check specs from registry (registered via @register decorator)
        if modname in check_registry:
            check_spec_registry[modname] = check_registry[modname]()
        else:
            check_spec_registry[modname] = []

    module_names.sort()
    return module_names, module_factories, check_spec_registry
