"""Integration tests for behavior tree engine with real modules."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus, Sequence, Selector
from websec_test.engine.decorators import Retry
from websec_test.engine.adapters import ModuleAdapter
from websec_test.results.models import TestStatus


HEADERS_ALL = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@pytest.fixture
def client():
    return SessionClient("http://example.com")


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target="http://example.com")


@responses.activate
def test_full_tree_execution(blackboard, client):
    responses.get("http://example.com/",
                  status=200,
                  headers=HEADERS_ALL)
    responses.get("http://example.com/login",
                  status=200,
                  body='<html><form action="/login" method="POST"><input name="password"></form></html>')
    responses.get("http://example.com/auth", status=404)
    responses.get("http://example.com/signin", status=404)
    responses.get("http://example.com/Login", status=404)
    responses.post("http://example.com/login", status=200)

    from websec_test.modules.headers import HeadersModule
    from websec_test.modules.auth import AuthModule

    tree = Sequence("full_scan", [
        ModuleAdapter("headers", HeadersModule()),
        ModuleAdapter("auth", AuthModule(target="http://example.com")),
    ])

    result = tree.tick(blackboard)
    assert len(blackboard.results) > 0
    assert any(r.module == "headers" for r in blackboard.results)
    assert any(r.module == "auth" for r in blackboard.results)


@responses.activate
def test_custom_tree(blackboard):
    responses.get("http://example.com/",
                  status=200,
                  headers=HEADERS_ALL)

    from websec_test.modules.headers import HeadersModule

    tree = Sequence("custom", [
        Retry("retry_headers", ModuleAdapter("headers", HeadersModule()), max_attempts=2),
    ])

    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == len(HEADERS_ALL)


@pytest.mark.slow
def test_regression_existing_tests():
    import subprocess
    import sys
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-v",
             "--ignore=tests/test_bt_integration.py",
             "--ignore=tests/test_integration.py"],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("Regression test suite timed out after 120s")
    print(result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout)
    assert result.returncode == 0, f"Existing tests failed:\n{result.stderr}"
