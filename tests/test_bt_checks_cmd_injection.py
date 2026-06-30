"""BT check-level tests for cmd_injection module."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.cmd_injection import CmdInjectionModule, cmd_injection_check_specs
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
def test_cmd_injection_pass_no_forms(client, blackboard):
    responses.get(TARGET + "/", status=200, body=NO_FORM_HTML)
    specs = cmd_injection_check_specs()
    tree = CheckTreeBuilder.build_module("cmd_injection", CmdInjectionModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS


@responses.activate
def test_cmd_injection_detected(client, blackboard):
    responses.get(TARGET + "/", status=200, body=FORM_HTML)
    responses.get(TARGET + "/search?q=%3B+ls", status=200,
                  body="uid=1000(john) gid=1000(john)")
    specs = cmd_injection_check_specs()
    tree = CheckTreeBuilder.build_module("cmd_injection", CmdInjectionModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    cmd = next(r for r in blackboard.results if r.test_name == "cmd_injection")
    assert cmd.status == TestStatus.FAIL
