"""Tests for check-level registry."""
from websec_test.engine.registry import register, check_registry
from websec_test.engine.builder import CheckSpec
from websec_test.results.models import Severity


def test_register_decorator():
    """@register stores factory in check_registry."""
    @register("test_mod")
    def factory():
        return []

    assert "test_mod" in check_registry
    assert callable(check_registry["test_mod"])
    assert check_registry["test_mod"]() == []

    # Clean up to avoid side effects
    check_registry.pop("test_mod", None)


def test_register_multiple():
    """Multiple registrations don't interfere."""
    @register("mod_a")
    def factory_a():
        return ["a"]

    @register("mod_b")
    def factory_b():
        return ["b"]

    assert "mod_a" in check_registry
    assert "mod_b" in check_registry
    assert check_registry["mod_a"]() == ["a"]
    assert check_registry["mod_b"]() == ["b"]

    check_registry.pop("mod_a", None)
    check_registry.pop("mod_b", None)


def test_register_overwrites():
    """Registering the same module name twice overwrites."""
    @register("dup_mod")
    def first():
        return ["first"]

    @register("dup_mod")
    def second():
        return ["second"]

    assert check_registry["dup_mod"]() == ["second"]

    check_registry.pop("dup_mod", None)


def test_registered_factories_return_check_specs():
    """Factories registered via @register should return CheckSpec instances."""

    # Use a minimal check function
    def dummy_check(client, target, bb):
        return None

    @register("spec_mod")
    def factory():
        return [
            CheckSpec("check1", dummy_check, severity=Severity.HIGH, module_name="spec_mod"),
            CheckSpec("check2", dummy_check, severity=Severity.LOW, module_name="spec_mod"),
        ]

    specs = check_registry["spec_mod"]()
    assert len(specs) == 2
    for spec in specs:
        assert isinstance(spec, CheckSpec)
        assert spec.module_name == "spec_mod"
    assert specs[0].name == "check1"
    assert specs[1].name == "check2"

    check_registry.pop("spec_mod", None)


def test_registry_is_dict():
    """check_registry is a module-level dict, ready for inspection."""
    from websec_test.engine.registry import check_registry as cr
    assert isinstance(cr, dict)
