"""Tests for behavior tree decorators."""
import time
import pytest
from websec_test.engine.nodes import Node, NodeStatus, Blackboard, Sequence
from websec_test.engine.leaves import Action
from websec_test.engine.decorators import Retry, Timeout, Invert, Cooldown, Log


# ── Helper actions ──────────────────────────────────────────────────

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
        self.last_bb = None

    def do_tick(self, blackboard):
        self.call_count += 1
        self.last_bb = blackboard
        return self.result


@pytest.fixture
def blackboard():
    return Blackboard(client="mock_client", target="http://example.com")


# ── Retry ───────────────────────────────────────────────────────────

def test_retry_succeeds_after_retry(blackboard):
    child = FailingAction("fails_twice", fail_count=2)
    retry = Retry("retry", child, max_attempts=3)
    assert retry.tick(blackboard) == NodeStatus.SUCCESS
    assert child.call_count == 3


def test_retry_exhausted(blackboard):
    child = FailingAction("always_fails", fail_count=999)
    retry = Retry("retry", child, max_attempts=3)
    assert retry.tick(blackboard) == NodeStatus.FAILURE
    assert child.call_count == 3


# ── Timeout ─────────────────────────────────────────────────────────

def test_timeout_exceeds(blackboard):
    child = SleepingAction("slow", duration=0.3)
    timeout = Timeout("t", child, max_seconds=0.05)
    result = timeout.tick(blackboard)
    assert result == NodeStatus.FAILURE


def test_timeout_within_limit(blackboard):
    child = SleepingAction("fast", duration=0.01, result=NodeStatus.SUCCESS)
    timeout = Timeout("t", child, max_seconds=1.0)
    assert timeout.tick(blackboard) == NodeStatus.SUCCESS


# ── Invert ──────────────────────────────────────────────────────────

def test_invert_flips(blackboard):
    fail_child = TrackedAction("fail", NodeStatus.FAILURE)
    inv = Invert("inv", fail_child)
    assert inv.tick(blackboard) == NodeStatus.SUCCESS

    success_child = TrackedAction("ok", NodeStatus.SUCCESS)
    inv2 = Invert("inv2", success_child)
    assert inv2.tick(blackboard) == NodeStatus.FAILURE


# ── Cooldown ────────────────────────────────────────────────────────

def test_cooldown_skips(blackboard):
    child = TrackedAction("counted")
    cd = Cooldown("cd", child, min_interval=60)
    cd.tick(blackboard)
    child.call_count = 0
    result = cd.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert child.call_count == 0


def test_cooldown_allows(blackboard):
    child = TrackedAction("counted")
    cd = Cooldown("cd", child, min_interval=0)
    cd.tick(blackboard)
    child.call_count = 0
    result = cd.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert child.call_count == 1


# ── Log ─────────────────────────────────────────────────────────────

def test_log_pass_through(blackboard, capsys):
    child = TrackedAction("inner", NodeStatus.FAILURE)
    log = Log("loggy", child, label="test_log")
    assert log.tick(blackboard) == NodeStatus.FAILURE
    captured = capsys.readouterr()
    assert "test_log" in captured.out
    assert "failure" in captured.out
