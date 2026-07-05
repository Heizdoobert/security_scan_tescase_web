"""Plugin loader — auto-discovers security modules from websec_test/modules/.

Eliminates the need to manually register new modules in main.py.
Convention: every .py file in modules/ (except __init__.py) is a module.
"""
import importlib
import inspect
import pkgutil


def discover_modules():
    """Scan websec_test.modules for module classes.

    Returns:
        module_names: list[str] — sorted dotted names (e.g. "configuration.headers")
        module_factories: dict[str, type] — dotted name → class
        short_name_map: dict[str, str] — short name → dotted name (e.g. "headers" → "configuration.headers")
    """
    import websec_test.modules as pkg

    module_names = []
    module_factories = {}
    short_name_map = {}
    for importer, modname, ispkg in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
        if ispkg:
            continue
        parts = modname.split(".")
        local_name = ".".join(parts[2:])
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
        short = parts[-1]
        if short not in short_name_map:
            short_name_map[short] = local_name
    module_names.sort()
    return module_names, module_factories, short_name_map
