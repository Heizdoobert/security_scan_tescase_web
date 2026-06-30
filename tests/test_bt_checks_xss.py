"""BT check-level tests for xss module."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.xss import XssModule, xss_check_specs
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
def test_xss_pass_no_forms(client, blackboard):
    responses.get(TARGET + "/", status=200, body=NO_FORM_HTML)
    specs = xss_check_specs()
    tree = CheckTreeBuilder.build_module("xss", XssModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS


@responses.activate
def test_xss_detected(client, blackboard):
    responses.get(TARGET + "/", status=200, body=FORM_HTML)
    responses.get(TARGET + "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", status=200,
                  body="<html><script>alert(1)</script></html>")
    specs = xss_check_specs()
    tree = CheckTreeBuilder.build_module("xss", XssModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    xss = next(r for r in blackboard.results if r.test_name == "xss_detection")
    assert xss.status == TestStatus.FAIL
