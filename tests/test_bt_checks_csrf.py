"""Integration tests for csrf check-level behavior tree."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.csrf import CSRFModule, csrf_check_specs
from websec_test.results.models import TestStatus

TARGET = "http://example.com"

FORM_HTML_NO_TOKEN = """
<html><body>
<form method="POST" action="/submit">
  <input name="email" type="text">
  <input type="submit">
</form>
</body></html>
"""

FORM_HTML_WITH_TOKEN = """
<html><body>
<form method="POST" action="/submit">
  <input name="email" type="text">
  <input name="csrf_token" type="hidden" value="abc123">
  <input type="submit">
</form>
</body></html>
"""


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_csrf_missing_token_pass(client, blackboard):
    """No POST forms -> PASS."""
    responses.get(TARGET + "/", status=200, body="<html><body>No forms here</body></html>")

    specs = csrf_check_specs()
    tree = CheckTreeBuilder.build_module("csrf", CSRFModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    missing = next(r for r in blackboard.results if r.test_name == "missing_csrf_token")
    assert missing.status == TestStatus.PASS


@responses.activate
def test_csrf_missing_token_fail(client, blackboard):
    """POST form without CSRF token -> FAIL."""
    responses.get(TARGET + "/", status=200, body=FORM_HTML_NO_TOKEN)
    responses.get(TARGET + "/submit", status=200, body="<form method='POST'></form>")

    specs = csrf_check_specs()
    tree = CheckTreeBuilder.build_module("csrf", CSRFModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    missing = next(r for r in blackboard.results if r.test_name == "missing_csrf_token")
    assert missing.status == TestStatus.FAIL


@responses.activate
def test_csrf_token_reuse_pass(client, blackboard):
    """Form with token that cannot be reused -> PASS."""
    responses.get(TARGET + "/", status=200, body=FORM_HTML_WITH_TOKEN)
    responses.get(TARGET + "/submit", status=200, body="<input name='csrf_token'>")
    responses.post(TARGET + "/submit", status=200, body="Accepted")
    responses.post(TARGET + "/submit", status=403, body="Rejected")

    specs = csrf_check_specs()
    tree = CheckTreeBuilder.build_module("csrf", CSRFModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    reuse = next(r for r in blackboard.results if r.test_name == "csrf_token_reuse")
    assert reuse.status == TestStatus.PASS


@responses.activate
def test_csrf_token_reuse_fail(client, blackboard):
    """Form with token that can be reused -> FAIL."""
    responses.get(TARGET + "/", status=200, body=FORM_HTML_WITH_TOKEN)
    responses.get(TARGET + "/submit", status=200, body="<input name='csrf_token'>")
    responses.post(TARGET + "/submit", status=200, body="Accepted")
    responses.post(TARGET + "/submit", status=200, body="Accepted again")

    specs = csrf_check_specs()
    tree = CheckTreeBuilder.build_module("csrf", CSRFModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    reuse = next(r for r in blackboard.results if r.test_name == "csrf_token_reuse")
    assert reuse.status == TestStatus.FAIL
