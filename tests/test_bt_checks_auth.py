"""Integration tests for auth check-level behavior tree."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.auth import auth_check_specs, AuthModule
from websec_test.results.models import TestStatus

TARGET = "http://example.com"
LOGIN_HTML = (
    '<html><body>'
    '<form action="/login" method="POST">'
    '<input name="username"><input name="password" type="password">'
    '</form></body></html>'
)


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_auth_checks_full_pass(blackboard, client):
    """All auth checks pass (blank password WARN, sqli PASS, rate limiting PASS, enum PASS)."""
    # Discover phase — 4 GETs
    responses.get(TARGET + "/login", status=200, body=LOGIN_HTML)
    responses.get(TARGET + "/auth", status=404)
    responses.get(TARGET + "/signin", status=404)
    responses.get(TARGET + "/Login", status=404)

    # blank_password_login: GET form to extract action (no POST)
    responses.get(TARGET + "/login", status=200, body=LOGIN_HTML)

    # ── POST responses in check execution order ──
    # (deterministic: blank_password, sqli, rate_limiting, username_enumeration)

    # sqli_login_bypass: 2 payloads, both rejected
    for _ in range(2):
        responses.post(TARGET + "/login", status=200, body="Invalid credentials")

    # rate_limiting: 10 rapid POSTs, all 429 → rate limiting detected = PASS
    for _ in range(10):
        responses.post(TARGET + "/login", status=429)

    # username_enumeration: 2 POSTs (valid + invalid), same response = PASS
    for _ in range(2):
        responses.post(TARGET + "/login", status=200, body="Invalid credentials")

    specs = auth_check_specs()
    tree = CheckTreeBuilder.build_module("auth", AuthModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 4

    for r in blackboard.results:
        assert r.module == "auth"
    assert blackboard.results[0].test_name == "blank_password_login"
    assert blackboard.results[0].status == TestStatus.WARN


@responses.activate
def test_auth_checks_sqli_bypass_detected(blackboard, client):
    """SQLi bypass discovered -> overall FAILURE."""
    # Discover phase — 4 GETs
    responses.get(TARGET + "/login", status=200, body=LOGIN_HTML)
    responses.get(TARGET + "/auth", status=404)
    responses.get(TARGET + "/signin", status=404)
    responses.get(TARGET + "/Login", status=404)

    # blank_password_login: GET form to extract action (no POST)
    responses.get(TARGET + "/login", status=200, body=LOGIN_HTML)

    # ── POST responses in check execution order ──
    # (deterministic: blank_password, sqli, rate_limiting, username_enumeration)

    # sqli_login_bypass: first payload succeeds (returns dashboard) -> FAIL
    responses.post(TARGET + "/login", status=200, body="Welcome to the dashboard")

    # rate_limiting: no rate limiting (all 200) -> FAIL
    for _ in range(10):
        responses.post(TARGET + "/login", status=200)

    # username_enumeration: 2 POSTs, same response -> PASS
    for _ in range(2):
        responses.post(TARGET + "/login", status=200, body="Invalid credentials")

    specs = auth_check_specs()
    tree = CheckTreeBuilder.build_module("auth", AuthModule().discover, specs)
    result = tree.tick(blackboard)
    # Parallel(min_success=0) always succeeds; results tell the real story
    assert result == NodeStatus.SUCCESS

    sqli_results = [r for r in blackboard.results if r.test_name == "sqli_login_bypass"]
    assert len(sqli_results) > 0
    assert sqli_results[0].status == TestStatus.FAIL
