"""Integration tests for authz check-level behavior tree."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.authz import authz_check_specs, AuthorizationModule
from websec_test.results.models import TestStatus
from websec_test.config.payloads import COMMON_PATHS

TARGET = "http://example.com"


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_authz_all_pass(blackboard, client):
    """All common paths blocked, no IDOR -> both PASS."""
    for path in COMMON_PATHS:
        responses.get(TARGET + path, status=404, body="Not found")
    for uid in range(1, 4):
        for p in [f"/user/{uid}", f"/profile/{uid}", f"/account/{uid}"]:
            responses.get(TARGET + p, status=404, body="Not found")
    responses.get(TARGET + "/", status=200, body="<html>Home</html>")

    specs = authz_check_specs()
    tree = CheckTreeBuilder.build_module("authz", AuthorizationModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 2
    for r in blackboard.results:
        assert r.status == TestStatus.PASS
        assert r.module == "authz"


@responses.activate
def test_authz_forced_browsing_open(blackboard, client):
    """One common path accessible -> forced_browsing FAIL."""
    # First COMMON_PATHS entry returns real content
    responses.get(TARGET + COMMON_PATHS[0], status=200,
                  body="<html><body>Admin panel with real content longer than 50 chars!</body></html>")
    for path in COMMON_PATHS[1:]:
        responses.get(TARGET + path, status=404, body="Not found")
    for uid in range(1, 4):
        for p in [f"/user/{uid}", f"/profile/{uid}", f"/account/{uid}"]:
            responses.get(TARGET + p, status=404, body="Not found")
    responses.get(TARGET + "/", status=200, body="<html>Home</html>")

    specs = authz_check_specs()
    tree = CheckTreeBuilder.build_module("authz", AuthorizationModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    fb = next(r for r in blackboard.results if r.test_name == "forced_browsing")
    assert fb.status == TestStatus.FAIL


@responses.activate
def test_authz_idor_detected(blackboard, client):
    """Sequential user endpoints accessible -> idor_check FAIL."""
    for path in COMMON_PATHS:
        responses.get(TARGET + path, status=404, body="Not found")
    for uid in range(1, 4):
        for p in [f"/user/{uid}", f"/profile/{uid}", f"/account/{uid}"]:
            if p == f"/user/{uid}":
                responses.get(TARGET + p, status=200, body="User data " * 20)
            else:
                responses.get(TARGET + p, status=404, body="Not found")
    responses.get(TARGET + "/", status=200, body="<html>Home</html>")

    specs = authz_check_specs()
    tree = CheckTreeBuilder.build_module("authz", AuthorizationModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    idor = next(r for r in blackboard.results if r.test_name == "idor_check")
    assert idor.status == TestStatus.FAIL
