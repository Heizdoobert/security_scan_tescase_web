"""Tests for ModuleAdapter."""
import pytest
import responses
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.adapters import ModuleAdapter
from websec_test.results.models import TestResult, TestStatus, Severity


class MockModule:
    def __init__(self, discover_result=None, test_result=None, raise_on_test=False):
        self.discover_result = discover_result or []
        self.test_result = test_result or []
        self.raise_on_test = raise_on_test
        self.discover_called_with = None
        self.test_called_with = None

    def discover(self, client, target):
        self.discover_called_with = (client, target)
        return self.discover_result

    def test(self, client, target, endpoints):
        self.test_called_with = (client, target, endpoints)
        if self.raise_on_test:
            raise RuntimeError("module exploded")
        return self.test_result


@pytest.fixture
def blackboard():
    return Blackboard(client="cli", target="http://example.com")


# ── Tests ───────────────────────────────────────────────────────────

def test_module_adapter_success(blackboard):
    module = MockModule(
        discover_result=["ep1"],
        test_result=[
            TestResult(module="mock", test_name="check1", status=TestStatus.PASS,
                       severity=Severity.LOW, endpoint="/", evidence="ok"),
        ],
    )
    adapter = ModuleAdapter("mock_mod", module)
    result = adapter.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 1
    assert blackboard.results[0].test_name == "check1"


def test_module_adapter_failure(blackboard):
    module = MockModule(
        discover_result=["ep1"],
        test_result=[
            TestResult(module="mock", test_name="check1", status=TestStatus.FAIL,
                       severity=Severity.HIGH, endpoint="/", evidence="broken"),
        ],
    )
    adapter = ModuleAdapter("mock_mod", module)
    result = adapter.tick(blackboard)
    assert result == NodeStatus.FAILURE
    assert len(blackboard.results) == 1


def test_module_adapter_exception(blackboard):
    module = MockModule(discover_result=["ep1"], raise_on_test=True)
    adapter = ModuleAdapter("mock_mod", module)
    result = adapter.tick(blackboard)
    assert result == NodeStatus.FAILURE
    assert len(blackboard.results) == 1
    assert blackboard.results[0].status == TestStatus.ERROR
    assert "module exploded" in blackboard.results[0].evidence


def test_module_adapter_discover_test_called(blackboard):
    module = MockModule(
        discover_result=["ep1", "ep2"],
        test_result=[
            TestResult(module="mock", test_name="t1", status=TestStatus.PASS,
                       severity=Severity.INFO, endpoint="/", evidence=""),
        ],
    )
    adapter = ModuleAdapter("mock_mod", module)
    adapter.tick(blackboard)
    assert module.discover_called_with == ("cli", "http://example.com")
    assert module.test_called_with[0] == "cli"
    assert module.test_called_with[1] == "http://example.com"
    assert module.test_called_with[2] == ["ep1", "ep2"]


@responses.activate
def test_module_adapter_real_module(blackboard):
    from websec_test.modules.headers import HeadersModule
    responses.get("http://example.com/",
                  status=200,
                  headers={"X-Frame-Options": "DENY"})
    adapter = ModuleAdapter("headers", HeadersModule())
    result = adapter.tick(blackboard)
    assert result in (NodeStatus.SUCCESS, NodeStatus.FAILURE)
    assert len(blackboard.results) > 0
    assert all(r.module == "headers" for r in blackboard.results)


# ── CheckAdapter Tests ───────────────────────────────────────────────

def dummy_check(client, target, endpoint):
    return TestResult(module="dummy", test_name="dummy_check", status=TestStatus.PASS,
                      severity=Severity.INFO, endpoint=str(endpoint), evidence="ok")


def test_check_adapter_success(blackboard):
    from websec_test.engine.adapters import CheckAdapter
    adapter = CheckAdapter("test_check", dummy_check, "/foo")
    result = adapter.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 1
    assert blackboard.results[0].test_name == "dummy_check"


def test_check_adapter_failure(blackboard):
    from websec_test.engine.adapters import CheckAdapter
    def fail_check(client, target, endpoint):
        return TestResult(module="dummy", test_name="fail", status=TestStatus.FAIL,
                          severity=Severity.HIGH, endpoint=str(endpoint), evidence="nope")
    adapter = CheckAdapter("fail_check", fail_check, "/bar")
    result = adapter.tick(blackboard)
    assert result == NodeStatus.FAILURE
    assert len(blackboard.results) == 1


def test_check_adapter_info_is_success(blackboard):
    from websec_test.engine.adapters import CheckAdapter
    def info_check(client, target, endpoint):
        return TestResult(module="dummy", test_name="info_test", status=TestStatus.INFO,
                          severity=Severity.INFO, endpoint=str(endpoint), evidence="info")
    adapter = CheckAdapter("info_check", info_check, "/baz")
    result = adapter.tick(blackboard)
    assert result == NodeStatus.SUCCESS


def test_check_adapter_warn_is_failure(blackboard):
    from websec_test.engine.adapters import CheckAdapter
    def warn_check(client, target, endpoint):
        return TestResult(module="dummy", test_name="warn", status=TestStatus.WARN,
                          severity=Severity.MEDIUM, endpoint=str(endpoint), evidence="warn")
    adapter = CheckAdapter("warn_check", warn_check, "/qux")
    result = adapter.tick(blackboard)
    assert result == NodeStatus.FAILURE


def test_check_adapter_calls_fn_with_correct_args(blackboard):
    from websec_test.engine.adapters import CheckAdapter
    captured = {}
    def capture(client, target, endpoint):
        captured.update(client=client, target=target, endpoint=endpoint)
        return TestResult(module="dummy", test_name="capture", status=TestStatus.PASS,
                          severity=Severity.INFO, endpoint=str(endpoint), evidence="")
    adapter = CheckAdapter("capture", capture, "/capture")
    adapter.tick(blackboard)
    assert captured["client"] == "cli"
    assert captured["target"] == "http://example.com"
    assert captured["endpoint"] == "/capture"
