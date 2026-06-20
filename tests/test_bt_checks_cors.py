"""Integration tests for CORS check-level behavior tree."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.cors import cors_check_specs, CorsModule
from websec_test.results.models import TestStatus

TARGET = "http://example.com"


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_cors_checks_all_pass(blackboard, client):
    """All CORS checks pass (restrictive CORS policy)."""
    responses.get(
        TARGET + "/", status=200,
        headers={"Access-Control-Allow-Origin": "https://trusted.com"},
    )
    specs = cors_check_specs()
    tree = CheckTreeBuilder.build_module("cors", CorsModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 3
    for r in blackboard.results:
        assert r.status == TestStatus.PASS
        assert r.module == "cors"


@responses.activate
def test_cors_checks_wildcard_fail(blackboard, client):
    """Wildcard origin detected -> FAILURE."""
    responses.get(
        TARGET + "/", status=200,
        headers={"Access-Control-Allow-Origin": "*"},
    )
    specs = cors_check_specs()
    tree = CheckTreeBuilder.build_module("cors", CorsModule().discover, specs)
    result = tree.tick(blackboard)
    # Parallel(min_success=0) always succeeds; results tell the real story
    assert result == NodeStatus.SUCCESS

    wildcard = [r for r in blackboard.results if r.test_name == "wildcard_origin"]
    assert len(wildcard) > 0
    assert wildcard[0].status == TestStatus.FAIL


@responses.activate
def test_cors_checks_credentials_with_wildcard(blackboard, client):
    """Credentials with wildcard -> FAILURE."""
    responses.get(
        TARGET + "/", status=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    specs = cors_check_specs()
    tree = CheckTreeBuilder.build_module("cors", CorsModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    creds = [r for r in blackboard.results if r.test_name == "credentials_with_wildcard"]
    assert len(creds) > 0
    assert creds[0].status == TestStatus.FAIL


@responses.activate
def test_cors_checks_reflected_origin(blackboard, client):
    """Reflected origin detected -> FAILURE."""
    responses.get(
        TARGET + "/", status=200,
        headers={"Access-Control-Allow-Origin": "https://attacker.com"},
    )
    specs = cors_check_specs()
    tree = CheckTreeBuilder.build_module("cors", CorsModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    reflected = [r for r in blackboard.results if r.test_name == "reflected_origin"]
    assert len(reflected) > 0
    assert reflected[0].status == TestStatus.FAIL
