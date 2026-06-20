from collections.abc import Callable

from websec_test.plugins.registry import registry


def register_module(
    name: str | None = None, category: str = "web-security"
) -> Callable[[type], type]:
    def wrapper(cls: type) -> type:
        module_name = name
        if module_name is None:
            module_name = cls.__name__.replace("Module", "").lower()
        check_specs_fn = getattr(cls, "check_specs", None)
        registry.register(
            cls=cls,
            name=module_name,
            category=category,
            check_specs_fn=check_specs_fn,
        )
        return cls

    return wrapper
