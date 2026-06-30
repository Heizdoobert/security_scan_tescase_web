"""BT check-level tests for sqli module."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.sqli import SqliModule, sqli_check_specs
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
def test_sqli_pass_no_forms(client, blackboard):
    responses.get(TARGET + "/", status=200, body=NO_FORM_HTML)
    specs = sqli_check_specs()
    tree = CheckTreeBuilder.build_module("sqli", SqliModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS


@responses.activate
def test_sqli_detected(client, blackboard):
    responses.get(TARGET + "/", status=200, body=FORM_HTML)
    responses.get(TARGET + "/search?q=", status=200, body="Results page")
    responses.get(TARGET + "/search?q=%27+OR+%271%27%3D%271", status=200,
                  body="SQL syntax error near ''")
    specs = sqli_check_specs()
    tree = CheckTreeBuilder.build_module("sqli", SqliModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    sqli = next(r for r in blackboard.results if r.test_name == "sqli_detection")
    assert sqli.status == TestStatus.FAIL
