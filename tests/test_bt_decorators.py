"""Tests for Retry, Timeout, Invert decorators."""
import time
import pytest
from websec_test.engine.nodes import Node, NodeStatus, Blackboard
from websec_test.engine.leaves import Action
from websec_test.engine.decorators import Decorator, Retry, Timeout, Invert


class FailingAction(Action):
    def __init__(self, name, fail_count=1):
        super().__init__(name)
        self.fail_count = fail_count
        self.call_count = 0
    def do_tick(self, blackboard):
        self.call_count += 1
        if self.call_count <= self.fail_count:
            return NodeStatus.FAILURE
        return NodeStatus.SUCCESS


class SleepingAction(Action):
    def __init__(self, name, duration, result=NodeStatus.SUCCESS):
        super().__init__(name)
        self.duration = duration
        self.result = result
    def do_tick(self, blackboard):
        time.sleep(self.duration)
        return self.result


class TrackedAction(Action):
    def __init__(self, name, result=NodeStatus.SUCCESS):
        super().__init__(name)
        self.result = result
        self.call_count = 0
    def do_tick(self, blackboard):
        self.call_count += 1
        return self.result


@pytest.fixture
def blackboard():
    return Blackboard(client="mock_client", target="http://example.com")


# ── Decorator base ──────────────────────────────────────────────────

def test_decorator_delegates(blackboard):
    child = TrackedAction("child", NodeStatus.FAILURE)
    d = Decorator("dec", child)
    assert d.tick(blackboard) == NodeStatus.FAILURE
    assert child.call_count == 1


# ── Retry ───────────────────────────────────────────────────────────

def test_retry_succeeds_on_first_try(blackboard):
    child = FailingAction("ok", fail_count=0)
    retry = Retry("retry", child, max_retries=2)
    assert retry.tick(blackboard) == NodeStatus.SUCCESS
    assert child.call_count == 1


def test_retry_succeeds_after_retries(blackboard):
    child = FailingAction("fails_twice", fail_count=2)
    retry = Retry("retry", child, max_retries=2)
    assert retry.tick(blackboard) == NodeStatus.SUCCESS
    assert child.call_count == 3


def test_retry_exhausted(blackboard):
    child = FailingAction("always_fails", fail_count=999)
    retry = Retry("retry", child, max_retries=2)
    assert retry.tick(blackboard) == NodeStatus.FAILURE
    assert child.call_count == 3


def test_retry_default_max_retries(blackboard):
    child = FailingAction("fails_once", fail_count=1)
    retry = Retry("retry", child)
    assert retry.tick(blackboard) == NodeStatus.SUCCESS
    assert child.call_count == 2


def test_retry_zero_retries(blackboard):
    child = FailingAction("fails_always", fail_count=1)
    retry = Retry("retry", child, max_retries=0)
    assert retry.tick(blackboard) == NodeStatus.FAILURE
    assert child.call_count == 1


# ── Timeout ─────────────────────────────────────────────────────────

def test_timeout_exceeds(blackboard):
    child = SleepingAction("slow", duration=0.3)
    timeout = Timeout("t", child, timeout=0.05)
    result = timeout.tick(blackboard)
    assert result == NodeStatus.FAILURE


def test_timeout_within_limit(blackboard):
    child = SleepingAction("fast", duration=0.01, result=NodeStatus.SUCCESS)
    timeout = Timeout("t", child, timeout=1.0)
    assert timeout.tick(blackboard) == NodeStatus.SUCCESS


def test_timeout_default(blackboard):
    child = SleepingAction("instant", duration=0.001, result=NodeStatus.SUCCESS)
    timeout = Timeout("t", child)
    assert timeout.tick(blackboard) == NodeStatus.SUCCESS


# ── Invert ──────────────────────────────────────────────────────────

def test_invert_success_to_failure(blackboard):
    child = TrackedAction("ok", NodeStatus.SUCCESS)
    inv = Invert("inv", child)
    assert inv.tick(blackboard) == NodeStatus.FAILURE


def test_invert_failure_to_success(blackboard):
    child = TrackedAction("fail", NodeStatus.FAILURE)
    inv = Invert("inv", child)
    assert inv.tick(blackboard) == NodeStatus.SUCCESS


def test_invert_running_unchanged(blackboard):
    child = TrackedAction("running", NodeStatus.RUNNING)
    inv = Invert("inv", child)
    assert inv.tick(blackboard) == NodeStatus.RUNNING
