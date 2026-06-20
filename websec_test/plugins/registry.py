import logging
from collections.abc import Callable


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, type] = {}
        self._categories: dict[str, list[str]] = {}
        self._descriptions: dict[str, str] = {}
        self._check_specs_fns: dict[str, Callable[[], list]] = {}

    def register(
        self,
        cls: type,
        name: str,
        category: str = "web-security",
        check_specs_fn: Callable[[], list] | None = None,
    ) -> None:
        if name in self._modules:
            logging.warning("Module %r already registered; overwriting", name)
        self._modules[name] = cls
        self._categories.setdefault(category, []).append(name)
        self._descriptions[name] = getattr(cls, "description", "")
        if check_specs_fn is not None:
            self._check_specs_fns[name] = check_specs_fn

    @property
    def all_modules(self) -> list[str]:
        return list(self._modules.keys())

    def by_category(self, category: str) -> list[str]:
        return list(self._categories.get(category, []))

    @property
    def categories(self) -> dict[str, list[str]]:
        return dict(self._categories)

    def get_check_specs(self, name: str) -> list:
        fn = self._check_specs_fns.get(name)
        return fn() if fn is not None else []

    def instantiate(self, name: str, **kwargs: object) -> object:
        cls = self._modules.get(name)
        if cls is None:
            raise KeyError(f"Unknown module: {name}")
        return cls(**kwargs)


registry = ModuleRegistry()
