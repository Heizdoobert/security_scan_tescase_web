from typing import Protocol, runtime_checkable


@runtime_checkable
class ModuleProtocol(Protocol):
    name: str
    description: str
    category: str

    def discover(self, context) -> list:
        ...

    def test(self, context, endpoints) -> list:
        ...


@runtime_checkable
class TargetProtocol(Protocol):
    @property
    def base_url(self) -> str:
        ...

    def request(self, req) -> object:
        ...


@runtime_checkable
class HasCheckSpecs(Protocol):
    def check_specs(self) -> list:
        ...
