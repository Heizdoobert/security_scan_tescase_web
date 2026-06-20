"""Tests for CheckAdapter and DiscoverAction."""
import pytest
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.adapters import CheckAdapter, DiscoverAction
from websec_test.results.models import TestResult, TestStatus, Severity

from collections import namedtuple
Endpoint = namedtuple("Endpoint", ["url", "method"])


@pytest.fixture
def blackboard():
    return Blackboard(client="cli", target="http://example.com")


# ── CheckAdapter ────────────────────────────────────────────────────────

def test_check_adapter_pass(blackboard):
    def check(client, target, bb):
        return TestResult(module="m", test_name="t", status=TestStatus.PASS,
                          severity=Severity.LOW, endpoint="/", evidence="ok")
    adapter = CheckAdapter("t", check, module_name="m")
    result = adapter.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 1
    assert blackboard.results[0].status == TestStatus.PASS


def test_check_adapter_fail(blackboard):
    def check(client, target, bb):
        return TestResult(module="m", test_name="t", status=TestStatus.FAIL,
                          severity=Severity.HIGH, endpoint="/", evidence="broken")
    adapter = CheckAdapter("t", check, module_name="m")
    result = adapter.tick(blackboard)
    assert result == NodeStatus.FAILURE
    assert blackboard.results[0].status == TestStatus.FAIL


def test_check_adapter_error_result(blackboard):
    def check(client, target, bb):
        return TestResult(module="m", test_name="t", status=TestStatus.ERROR,
                          severity=Severity.HIGH, endpoint="/", evidence="error")
    adapter = CheckAdapter("t", check, module_name="m")
    result = adapter.tick(blackboard)
    assert result == NodeStatus.FAILURE
    assert blackboard.results[0].status == TestStatus.ERROR


def test_check_adapter_skip(blackboard):
    """None result from check_fn means skip — returns SUCCESS, no result stored."""
    def check(client, target, bb):
        return None
    adapter = CheckAdapter("t", check, module_name="m")
    result = adapter.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 0


def test_check_adapter_exception(blackboard):
    def check(client, target, bb):
        raise RuntimeError("boom")
    adapter = CheckAdapter("t", check, module_name="m")
    result = adapter.tick(blackboard)
    assert result == NodeStatus.FAILURE
    assert len(blackboard.results) == 1
    assert blackboard.results[0].status == TestStatus.ERROR
    assert "boom" in blackboard.results[0].evidence


def test_check_adapter_blackboard_passthrough(blackboard):
    """Check function receives the real blackboard and can read/write."""
    blackboard.set("my_key", "my_value")

    def check(client, target, bb):
        assert bb.get("my_key") == "my_value"
        return TestResult(module="m", test_name="t", status=TestStatus.PASS,
                          severity=Severity.INFO, endpoint="/", evidence="ok")
    adapter = CheckAdapter("t", check, module_name="m")
    assert adapter.tick(blackboard) == NodeStatus.SUCCESS


def test_check_adapter_exception_uses_module_name(blackboard):
    """module_name is used for the error result when check_fn raises."""
    def check(client, target, bb):
        raise RuntimeError("boom")
    adapter = CheckAdapter("my_check", check, module_name="explicit")
    adapter.tick(blackboard)
    assert len(blackboard.results) == 1
    assert blackboard.results[0].module == "explicit"
    assert blackboard.results[0].test_name == "my_check"


# ── DiscoverAction ─────────────────────────────────────────────────────

def test_discover_action_success(blackboard):
    def discover(client, target):
        return [Endpoint(url="/", method="GET")]
    da = DiscoverAction("test_mod", discover)
    result = da.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert blackboard.get("test_mod_endpoints") == [Endpoint(url="/", method="GET")]


def test_discover_action_empty(blackboard):
    def discover(client, target):
        return []
    da = DiscoverAction("test_mod", discover)
    result = da.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert blackboard.get("test_mod_endpoints") == []


def test_discover_action_none(blackboard):
    def discover(client, target):
        return None
    da = DiscoverAction("test_mod", discover)
    result = da.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert blackboard.get("test_mod_endpoints") == []
