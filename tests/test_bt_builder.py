"""Tests for CheckTreeBuilder and CheckSpec."""
import pytest
from websec_test.engine.builder import CheckSpec, CheckTreeBuilder
from websec_test.engine.nodes import Sequence, SequentialGroup, NodeStatus, Blackboard
from websec_test.engine.adapters import CheckAdapter, DiscoverAction
from websec_test.results.models import Severity


def make_check(name, depends_on=None):
    return CheckSpec(name, lambda c, t, bb: None,
                     severity=Severity.LOW, module_name="test",
                     depends_on=depends_on)


def make_node(name):
    return CheckAdapter(name, lambda c, t, bb: None, module_name="test")


# ── CheckSpec ───────────────────────────────────────────────────────────

def test_check_spec_defaults():
    spec = CheckSpec("my_check", lambda: None, severity=Severity.HIGH)
    assert spec.name == "my_check"
    assert spec.depends_on is None
    assert spec.module_name == ""


def test_check_spec_full():
    spec = CheckSpec("full", lambda: None, severity=Severity.CRITICAL,
                     depends_on=["other"], module_name="mod")
    assert spec.depends_on == ["other"]
    assert spec.module_name == "mod"


# ── CheckTreeBuilder._group_by_dependency ──────────────────────────────

def test_group_no_deps():
    specs = [make_check("a"), make_check("b")]
    nodes = {s.name: make_node(s.name) for s in specs}
    groups = CheckTreeBuilder._group_by_dependency(specs, nodes)
    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_group_with_deps():
    specs = [
        make_check("a"),
        make_check("b", depends_on=["a"]),
        make_check("c", depends_on=["a"]),
    ]
    nodes = {s.name: make_node(s.name) for s in specs}
    groups = CheckTreeBuilder._group_by_dependency(specs, nodes)
    assert len(groups) == 2
    assert len(groups[0]) == 1  # a
    assert len(groups[1]) == 2  # b, c


def test_group_chained_deps():
    specs = [
        make_check("a"),
        make_check("b", depends_on=["a"]),
        make_check("c", depends_on=["b"]),
    ]
    nodes = {s.name: make_node(s.name) for s in specs}
    groups = CheckTreeBuilder._group_by_dependency(specs, nodes)
    assert len(groups) == 3
    assert len(groups[0]) == 1  # a
    assert len(groups[1]) == 1  # b
    assert len(groups[2]) == 1  # c


def test_group_circular_deps():
    """Circular deps should still resolve (all in one group)."""
    specs = [
        make_check("a", depends_on=["b"]),
        make_check("b", depends_on=["a"]),
    ]
    nodes = {s.name: make_node(s.name) for s in specs}
    groups = CheckTreeBuilder._group_by_dependency(specs, nodes)
    # Both end up in one group rather than hanging
    assert len(groups) >= 1
    all_names = set()
    for g in groups:
        for n in g:
            all_names.add(n.name)
    assert all_names == {"a", "b"}


# ── CheckTreeBuilder.build_module ───────────────────────────────────────

def test_build_module_no_deps():
    spec = make_check("only_check")
    specs = [spec]
    discover = lambda c, t: ["/"]
    root = CheckTreeBuilder.build_module("test_mod", discover, specs)

    assert isinstance(root, Sequence)
    assert root.name == "test_mod"
    assert isinstance(root.children[0], DiscoverAction)

    # Second child should be SequentialGroup (single group, no deps)
    check_group = root.children[1]
    assert isinstance(check_group, SequentialGroup)
    assert check_group.name == "test_mod_checks"
    assert len(check_group.children) == 1
    assert isinstance(check_group.children[0], CheckAdapter)


def test_build_module_with_deps():
    specs = [
        make_check("a"),
        make_check("b", depends_on=["a"]),
    ]
    discover = lambda c, t: ["/"]
    root = CheckTreeBuilder.build_module("test_mod", discover, specs)

    assert isinstance(root, Sequence)
    assert isinstance(root.children[0], DiscoverAction)

    # Second child should be Sequence of SequentialGroup groups
    check_group = root.children[1]
    assert isinstance(check_group, Sequence)
    assert check_group.name == "test_mod_checks"
    assert len(check_group.children) == 2
    assert isinstance(check_group.children[0], SequentialGroup)
    assert isinstance(check_group.children[1], SequentialGroup)
