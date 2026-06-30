"""Tests for Selector, Parallel, Condition nodes."""
import pytest
from websec_test.engine.nodes import Node, NodeStatus, Blackboard, Sequence, Selector, Parallel
from websec_test.engine.leaves import Action, Condition


class SimpleAction(Action):
    def __init__(self, name, result=NodeStatus.SUCCESS):
        super().__init__(name)
        self.result = result
        self.ticked = False
    def do_tick(self, blackboard):
        self.ticked = True
        return self.result


class CounterAction(Action):
    def __init__(self, name, returns=NodeStatus.SUCCESS):
        super().__init__(name)
        self.returns = returns
        self.tick_count = 0
    def do_tick(self, blackboard):
        self.tick_count += 1
        return self.returns


@pytest.fixture
def blackboard():
    return Blackboard(client="mock_client", target="http://example.com")


# ── Selector ────────────────────────────────────────────────────────

def test_selector_first_success(blackboard):
    a1 = SimpleAction("a1", NodeStatus.SUCCESS)
    a2 = SimpleAction("a2", NodeStatus.FAILURE)
    sel = Selector("sel", [a1, a2])
    assert sel.tick(blackboard) == NodeStatus.SUCCESS
    assert not a2.ticked


def test_selector_first_running(blackboard):
    a1 = SimpleAction("a1", NodeStatus.RUNNING)
    a2 = SimpleAction("a2", NodeStatus.SUCCESS)
    sel = Selector("sel", [a1, a2])
    assert sel.tick(blackboard) == NodeStatus.RUNNING
    assert not a2.ticked


def test_selector_all_fail(blackboard):
    sel = Selector("sel", [
        SimpleAction("a1", NodeStatus.FAILURE),
        SimpleAction("a2", NodeStatus.FAILURE),
    ])
    assert sel.tick(blackboard) == NodeStatus.FAILURE


def test_selector_empty(blackboard):
    sel = Selector("empty", [])
    assert sel.tick(blackboard) == NodeStatus.FAILURE


def test_selector_second_succeeds(blackboard):
    sel = Selector("sel", [
        SimpleAction("a1", NodeStatus.FAILURE),
        SimpleAction("a2", NodeStatus.SUCCESS),
        SimpleAction("a3", NodeStatus.FAILURE),
    ])
    assert sel.tick(blackboard) == NodeStatus.SUCCESS


# ── Parallel ────────────────────────────────────────────────────────

def test_parallel_all_success(blackboard):
    p = Parallel("p", [
        SimpleAction("a1", NodeStatus.SUCCESS),
        SimpleAction("a2", NodeStatus.SUCCESS),
    ], min_success=2)
    assert p.tick(blackboard) == NodeStatus.SUCCESS


def test_parallel_meets_threshold(blackboard):
    p = Parallel("p", [
        SimpleAction("a1", NodeStatus.SUCCESS),
        SimpleAction("a2", NodeStatus.FAILURE),
        SimpleAction("a3", NodeStatus.SUCCESS),
    ], min_success=2)
    assert p.tick(blackboard) == NodeStatus.SUCCESS


def test_parallel_below_threshold(blackboard):
    p = Parallel("p", [
        SimpleAction("a1", NodeStatus.SUCCESS),
        SimpleAction("a2", NodeStatus.FAILURE),
    ], min_success=2)
    assert p.tick(blackboard) == NodeStatus.FAILURE


def test_parallel_runs_all_children(blackboard):
    a2 = CounterAction("a2", NodeStatus.FAILURE)
    p = Parallel("p", [
        CounterAction("a1", NodeStatus.SUCCESS),
        a2,
    ], min_success=1)
    assert p.tick(blackboard) == NodeStatus.SUCCESS
    assert a2.tick_count == 1


def test_parallel_empty(blackboard):
    p = Parallel("empty", [], min_success=0)
    assert p.tick(blackboard) == NodeStatus.SUCCESS


def test_parallel_default_min_success(blackboard):
    p = Parallel("p", [
        SimpleAction("a1", NodeStatus.SUCCESS),
    ])
    assert p.tick(blackboard) == NodeStatus.SUCCESS


# ── Condition ───────────────────────────────────────────────────────

def test_condition_true(blackboard):
    cond = Condition("is_true", lambda bb: True)
    assert cond.tick(blackboard) == NodeStatus.SUCCESS


def test_condition_false(blackboard):
    cond = Condition("is_false", lambda bb: False)
    assert cond.tick(blackboard) == NodeStatus.FAILURE


def test_condition_receives_blackboard(blackboard):
    blackboard.set("val", 42)
    cond = Condition("check_bb", lambda bb: bb.get("val") == 42)
    assert cond.tick(blackboard) == NodeStatus.SUCCESS


def test_condition_exception_returns_failure(blackboard):
    cond = Condition("broken", lambda bb: 1 / 0)
    assert cond.tick(blackboard) == NodeStatus.FAILURE
