"""Tests for CheckTreeBuilder."""
import pytest
from websec_test.engine.nodes import NodeStatus, Blackboard, Sequence, Selector
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.engine.decorators import Retry
from websec_test.results.models import TestResult, TestStatus, Severity


class MockCheckModule:
    def __init__(self):
        self.discover_called = False
    def discover(self, client, target):
        self.discover_called = True
        return [type("EP", (), {"url": "/", "path": "/"})()]
    def check_pass(self, client, target, endpoint):
        return TestResult(module="mock", test_name="check_pass", status=TestStatus.PASS,
                          severity=Severity.LOW, endpoint="/", evidence="ok")
    def check_fail(self, client, target, endpoint):
        return TestResult(module="mock", test_name="check_fail", status=TestStatus.FAIL,
                          severity=Severity.HIGH, endpoint="/", evidence="broken")


@pytest.fixture
def bb():
    return Blackboard(client="x", target="http://x")


def test_builder_creates_sequence_tree(bb):
    module = MockCheckModule()
    eps = [type("EP", (), {"url": "/", "path": "/"})()]
    tree = CheckTreeBuilder.build(module, "mock_module", eps)
    assert tree.name == "mock_module"
    assert isinstance(tree, Sequence)
    assert len(tree.children) == 1


def test_builder_children_wrapped_in_retry(bb):
    module = MockCheckModule()
    eps = [type("EP", (), {"url": "/", "path": "/"})()]
    tree = CheckTreeBuilder.build(module, "mock_module", eps)
    endpoint_seq = tree.children[0]
    for child in endpoint_seq.children:
        assert isinstance(child, Retry)


def test_builder_supports_selector_groups(bb):
    module = MockCheckModule()
    module.SELECTOR_GROUPS = {"tech_group": ["check_pass"]}
    eps = [type("EP", (), {"url": "/", "path": "/"})()]
    tree = CheckTreeBuilder.build(module, "mock_module", eps)
    endpoint_seq = tree.children[0]
    assert isinstance(endpoint_seq.children[0], Selector)


def test_builder_empty_endpoints(bb):
    module = MockCheckModule()
    tree = CheckTreeBuilder.build(module, "empty", [])
    assert tree.name == "empty"
    assert len(tree.children) == 0
