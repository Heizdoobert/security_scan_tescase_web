"""Integration tests for injection check-level behavior tree."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.injection import InjectionModule, injection_check_specs
from websec_test.results.models import TestStatus

TARGET = "http://example.com"

FORM_HTML = """
<html><body>
<form method="GET" action="/search">
  <input name="q" type="text">
  <input type="submit">
</form>
</body></html>
"""

NO_FORM_HTML = "<html><body>Welcome</body></html>"


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_injection_all_pass(client, blackboard):
    """No forms -> all PASS."""
    responses.get(TARGET + "/", status=200, body=NO_FORM_HTML)

    specs = injection_check_specs()
    tree = CheckTreeBuilder.build_module("injection", InjectionModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    for r in blackboard.results:
        assert r.status == TestStatus.PASS


@responses.activate
def test_injection_sqli_detected(client, blackboard):
    """SQL error reflected -> FAIL."""
    responses.get(TARGET + "/", status=200, body=FORM_HTML)
    responses.get(TARGET + "/search?q=", status=200, body="Results page")
    responses.get(TARGET + "/search?q=%27+OR+%271%27%3D%271", status=200,
                  body="SQL syntax error near ''")

    specs = injection_check_specs()
    tree = CheckTreeBuilder.build_module("injection", InjectionModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    sqli = next(r for r in blackboard.results if r.test_name == "sqli_detection")
    assert sqli.status == TestStatus.FAIL
    xss = next(r for r in blackboard.results if r.test_name == "xss_detection")
    assert xss.status == TestStatus.PASS
    cmd = next(r for r in blackboard.results if r.test_name == "cmd_injection")
    assert cmd.status == TestStatus.PASS


@responses.activate
def test_injection_xss_detected(client, blackboard):
    """XSS payload reflected -> FAIL."""
    responses.get(TARGET + "/", status=200, body=FORM_HTML)
    responses.get(TARGET + "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", status=200,
                  body="<html><script>alert(1)</script></html>")

    specs = injection_check_specs()
    tree = CheckTreeBuilder.build_module("injection", InjectionModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    xss = next(r for r in blackboard.results if r.test_name == "xss_detection")
    assert xss.status == TestStatus.FAIL


@responses.activate
def test_injection_cmd_injection_detected(client, blackboard):
    """Command output reflected -> FAIL."""
    responses.get(TARGET + "/", status=200, body=FORM_HTML)
    responses.get(TARGET + "/search?q=%3B+ls", status=200,
                  body="uid=1000(john) gid=1000(john)")

    specs = injection_check_specs()
    tree = CheckTreeBuilder.build_module("injection", InjectionModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    cmd = next(r for r in blackboard.results if r.test_name == "cmd_injection")
    assert cmd.status == TestStatus.FAIL
