"""BT check-level tests for nosql module."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.nosql import NosqlModule, nosql_check_specs
from websec_test.results.models import TestStatus

TARGET = "http://example.com"
FORM_HTML = """<html><body>
<form method="GET" action="/search">
  <input name="q" type="text">
  <input type="submit">
</form>
</body></html>"""
NO_FORM_HTML = "<html><body>Welcome</body></html>"


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_nosql_pass_no_forms(client, blackboard):
    responses.get(TARGET + "/", status=200, body=NO_FORM_HTML)
    specs = nosql_check_specs()
    tree = CheckTreeBuilder.build_module("nosql", NosqlModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS


@responses.activate
def test_nosql_bypass_detected(client, blackboard):
    responses.get(TARGET + "/", status=200, body=FORM_HTML)
    responses.get(TARGET + "/search?q=invalid__test__value", status=200,
                  body="invalid password")
    responses.get(TARGET + "/search?q%5B%24ne%5D=", status=200,
                  body="welcome admin")
    specs = nosql_check_specs()
    tree = CheckTreeBuilder.build_module("nosql", NosqlModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    nosql = next(r for r in blackboard.results if r.test_name == "nosql_injection")
    assert nosql.status == TestStatus.FAIL
