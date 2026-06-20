"""Check-level registry for module check functions."""
from typing import Callable

check_registry: dict[str, Callable[[], list["CheckSpec"]]] = {}


def register(module_name: str):
    """Decorator that registers a check-spec factory for a module."""
    def wrapper(fn):
        check_registry[module_name] = fn
        return fn
    return wrapper
