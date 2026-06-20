"""Dedicated tests for Blackboard functionality."""
import pytest
from websec_test.engine.nodes import Blackboard
from websec_test.results.models import TestResult, TestStatus, Severity


@pytest.fixture
def blackboard():
    return Blackboard(client="my_client", target="http://target.test")


# ── Initialization ──────────────────────────────────────────────────

def test_blackboard_initialization(blackboard):
    assert blackboard.client == "my_client"
    assert blackboard.target == "http://target.test"
    assert blackboard.results == []
    assert blackboard._store == {}


# ── add_result ──────────────────────────────────────────────────────

def test_blackboard_add_result(blackboard):
    r1 = TestResult(module="m", test_name="t1", status=TestStatus.PASS,
                    severity=Severity.LOW, endpoint="/")
    r2 = TestResult(module="m", test_name="t2", status=TestStatus.FAIL,
                    severity=Severity.HIGH, endpoint="/")
    blackboard.add_result(r1)
    blackboard.add_result(r2)
    assert len(blackboard.results) == 2
    assert blackboard.results[0].test_name == "t1"
    assert blackboard.results[1].test_name == "t2"


# ── get/set ─────────────────────────────────────────────────────────

def test_blackboard_get_set(blackboard):
    blackboard.set("score", 100)
    blackboard.set("name", "test")
    assert blackboard.get("score") == 100
    assert blackboard.get("name") == "test"


def test_blackboard_get_default(blackboard):
    assert blackboard.get("missing") is None
    assert blackboard.get("missing", 42) == 42


def test_blackboard_key_isolation(blackboard):
    blackboard.set("a", 1)
    blackboard.set("b", 2)
    assert blackboard.get("a") == 1
    assert blackboard.get("b") == 2
