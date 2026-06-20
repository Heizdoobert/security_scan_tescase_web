"""Integration tests for methods check-level behavior tree."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.methods import MethodsModule, methods_check_specs
from websec_test.results.models import TestStatus

TARGET = "http://example.com"


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_methods_all_pass(client, blackboard):
    """All methods blocked -> all PASS."""
    responses.options(TARGET + "/", status=200, headers={"Allow": "GET, HEAD, OPTIONS"})
    responses.get(TARGET + "/", status=200, body="Home")
    responses.post(TARGET + "/", status=200, body="Home")
    for method in ["TRACE", "PUT", "DELETE"]:
        responses.add(method=method, url=TARGET + "/", status=405, body="Not Allowed")
        responses.add(method=method, url=TARGET + "/admin", status=405, body="Not Allowed")

    specs = methods_check_specs()
    tree = CheckTreeBuilder.build_module("methods", MethodsModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    for r in blackboard.results:
        assert r.status == TestStatus.PASS, f"{r.test_name} was not PASS"


@responses.activate
def test_methods_dangerous_methods_detected(client, blackboard):
    """PUT enabled -> FAIL."""
    responses.options(TARGET + "/", status=200, headers={"Allow": "GET, PUT, POST"})
    responses.get(TARGET + "/", status=200, body="Home")
    responses.post(TARGET + "/", status=200, body="Home")
    responses.put(TARGET + "/", status=200, body="Created")
    responses.delete(TARGET + "/", status=405, body="Not Allowed")
    responses.add(method="TRACE", url=TARGET + "/admin", status=405, body="Not Allowed")

    specs = methods_check_specs()
    tree = CheckTreeBuilder.build_module("methods", MethodsModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    put = next(r for r in blackboard.results if r.test_name == "put_method_enabled")
    assert put.status == TestStatus.FAIL
    delete = next(r for r in blackboard.results if r.test_name == "delete_method_enabled")
    assert delete.status == TestStatus.PASS
    trace = next(r for r in blackboard.results if r.test_name == "trace_method_enabled")
    assert trace.status == TestStatus.PASS


@responses.activate
def test_methods_options_reveals_dangerous(client, blackboard):
    """OPTIONS reveals PUT, DELETE -> FAIL."""
    responses.options(TARGET + "/", status=200,
                      headers={"Allow": "GET, HEAD, PUT, DELETE, OPTIONS, TRACE"})
    responses.get(TARGET + "/", status=200, body="Home")
    responses.post(TARGET + "/", status=200, body="Home")
    for method in ["TRACE", "PUT", "DELETE"]:
        responses.add(method=method, url=TARGET + "/", status=405, body="Not Allowed")
        responses.add(method=method, url=TARGET + "/admin", status=405, body="Not Allowed")

    specs = methods_check_specs()
    tree = CheckTreeBuilder.build_module("methods", MethodsModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    opt = next(r for r in blackboard.results if r.test_name == "options_allow_enumeration")
    assert opt.status == TestStatus.FAIL
