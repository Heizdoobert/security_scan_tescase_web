"""Integration tests for headers check-level behavior tree."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.headers import headers_check_specs, HeadersModule
from websec_test.results.models import TestStatus

TARGET = "http://example.com"


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_headers_checks_all_missing(blackboard, client):
    """All headers missing -> each check returns FAIL."""
    responses.get(TARGET + "/", status=200, body="<html></html>")
    specs = headers_check_specs()
    tree = CheckTreeBuilder.build_module("headers", HeadersModule().discover, specs)
    result = tree.tick(blackboard)
    # Parallel(min_success=0) always succeeds; results tell the real story
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == len(specs)
    for r in blackboard.results:
        assert r.status == TestStatus.FAIL
        assert r.module == "headers"


@responses.activate
def test_headers_checks_all_present(blackboard, client):
    """All headers present -> each check returns PASS."""
    all_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }
    responses.get(TARGET + "/", status=200, headers=all_headers)
    specs = headers_check_specs()
    tree = CheckTreeBuilder.build_module("headers", HeadersModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == len(specs)
    for r in blackboard.results:
        assert r.status == TestStatus.PASS
        assert r.module == "headers"


@responses.activate
def test_headers_checks_partial(blackboard, client):
    """Some headers present, some missing -> mixed results."""
    partial_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }
    responses.get(TARGET + "/", status=200, headers=partial_headers)
    specs = headers_check_specs()
    tree = CheckTreeBuilder.build_module("headers", HeadersModule().discover, specs)
    result = tree.tick(blackboard)

    # Parallel(min_success=0) always succeeds; results tell the real story
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == len(specs)

    passed = [r for r in blackboard.results if r.status == TestStatus.PASS]
    failed = [r for r in blackboard.results if r.status == TestStatus.FAIL]
    assert len(passed) == 3
    assert len(failed) == 5
    assert all(r.module == "headers" for r in blackboard.results)
