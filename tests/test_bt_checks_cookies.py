"""Integration tests for cookies check-level behavior tree."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.cookies import cookies_check_specs, CookiesModule
from websec_test.results.models import TestStatus

TARGET = "http://example.com"


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_cookies_no_cookies_all_pass(blackboard, client):
    """No cookies set -> all checks PASS."""
    responses.get(TARGET + "/", status=200, body="<html></html>")
    specs = cookies_check_specs()
    tree = CheckTreeBuilder.build_module("cookies", CookiesModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 3
    for r in blackboard.results:
        assert r.status == TestStatus.PASS
        assert r.module == "cookies"


@responses.activate
def test_cookies_all_flags_present(blackboard, client):
    """All cookies have Secure, HttpOnly, SameSite flags -> all PASS."""
    responses.get(
        TARGET + "/", status=200,
        headers={"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax"},
    )
    specs = cookies_check_specs()
    tree = CheckTreeBuilder.build_module("cookies", CookiesModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 3
    for r in blackboard.results:
        assert r.status == TestStatus.PASS
        assert r.module == "cookies"


@responses.activate
def test_cookies_missing_secure_flag(blackboard, client):
    """Cookie missing Secure flag -> missing_secure_flag FAIL, others PASS."""
    responses.get(
        TARGET + "/", status=200,
        headers={"Set-Cookie": "session=abc123; HttpOnly; SameSite=Lax"},
    )
    specs = cookies_check_specs()
    tree = CheckTreeBuilder.build_module("cookies", CookiesModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    secure = [r for r in blackboard.results if r.test_name == "missing_secure_flag"]
    httponly = [r for r in blackboard.results if r.test_name == "missing_httponly_flag"]
    samesite = [r for r in blackboard.results if r.test_name == "missing_samesite_flag"]
    assert len(secure) == 1 and secure[0].status == TestStatus.FAIL
    assert len(httponly) == 1 and httponly[0].status == TestStatus.PASS
    assert len(samesite) == 1 and samesite[0].status == TestStatus.PASS


@responses.activate
def test_cookies_missing_httponly_flag(blackboard, client):
    """Cookie missing HttpOnly flag -> missing_httponly_flag FAIL, others PASS."""
    responses.get(
        TARGET + "/", status=200,
        headers={"Set-Cookie": "session=abc123; Secure; SameSite=Lax"},
    )
    specs = cookies_check_specs()
    tree = CheckTreeBuilder.build_module("cookies", CookiesModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    secure = [r for r in blackboard.results if r.test_name == "missing_secure_flag"]
    httponly = [r for r in blackboard.results if r.test_name == "missing_httponly_flag"]
    samesite = [r for r in blackboard.results if r.test_name == "missing_samesite_flag"]
    assert len(secure) == 1 and secure[0].status == TestStatus.PASS
    assert len(httponly) == 1 and httponly[0].status == TestStatus.FAIL
    assert len(samesite) == 1 and samesite[0].status == TestStatus.PASS


@responses.activate
def test_cookies_missing_samesite_flag(blackboard, client):
    """Cookie missing SameSite flag -> missing_samesite_flag FAIL, others PASS."""
    responses.get(
        TARGET + "/", status=200,
        headers={"Set-Cookie": "session=abc123; Secure; HttpOnly"},
    )
    specs = cookies_check_specs()
    tree = CheckTreeBuilder.build_module("cookies", CookiesModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    secure = [r for r in blackboard.results if r.test_name == "missing_secure_flag"]
    httponly = [r for r in blackboard.results if r.test_name == "missing_httponly_flag"]
    samesite = [r for r in blackboard.results if r.test_name == "missing_samesite_flag"]
    assert len(secure) == 1 and secure[0].status == TestStatus.PASS
    assert len(httponly) == 1 and httponly[0].status == TestStatus.PASS
    assert len(samesite) == 1 and samesite[0].status == TestStatus.FAIL
