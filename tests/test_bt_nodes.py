"""Tests for behavior tree composite nodes."""
import pytest
from websec_test.engine.nodes import Node, NodeStatus, Blackboard, Sequence, Selector, SequentialGroup
from websec_test.engine.leaves import Action


# ── Helper actions for testing ──────────────────────────────────────

class CounterAction(Action):
    def __init__(self, name, returns, fail_after=None):
        super().__init__(name)
        self.returns = returns
        self.tick_count = 0
        self.fail_after = fail_after

    def do_tick(self, blackboard):
        self.tick_count += 1
        if self.fail_after is not None and self.tick_count > self.fail_after:
            return NodeStatus.FAILURE
        return self.returns


class SimpleAction(Action):
    def __init__(self, name, result=NodeStatus.SUCCESS):
        super().__init__(name)
        self.result = result
        self.ticked = False

    def do_tick(self, blackboard):
        self.ticked = True
        return self.result


# ── Fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def blackboard():
    return Blackboard(client="mock_client", target="http://example.com")


# ── NodeStatus ──────────────────────────────────────────────────────

def test_node_status_enum():
    assert NodeStatus.SUCCESS.value == "success"
    assert NodeStatus.FAILURE.value == "failure"
    assert NodeStatus.RUNNING.value == "running"


def test_node_abstract():
    with pytest.raises(TypeError):
        Node("abstract")


# ── Blackboard ──────────────────────────────────────────────────────

def test_blackboard_add_result(blackboard):
    blackboard.add_result("r1")
    blackboard.add_result("r2")
    assert blackboard.results == ["r1", "r2"]


def test_blackboard_get_set(blackboard):
    blackboard.set("key1", "val1")
    assert blackboard.get("key1") == "val1"


def test_blackboard_default(blackboard):
    assert blackboard.get("nonexistent") is None
    assert blackboard.get("nonexistent", 42) == 42


# ── Sequence ────────────────────────────────────────────────────────

def test_sequence_all_success(blackboard):
    seq = Sequence("seq", [
        SimpleAction("a1", NodeStatus.SUCCESS),
        SimpleAction("a2", NodeStatus.SUCCESS),
        SimpleAction("a3", NodeStatus.SUCCESS),
    ])
    assert seq.tick(blackboard) == NodeStatus.SUCCESS


def test_sequence_short_circuit(blackboard):
    a2 = SimpleAction("a2", NodeStatus.FAILURE)
    a3 = SimpleAction("a3", NodeStatus.SUCCESS)
    seq = Sequence("seq", [
        SimpleAction("a1", NodeStatus.SUCCESS),
        a2,
        a3,
    ])
    assert seq.tick(blackboard) == NodeStatus.FAILURE
    assert not a3.ticked, "third child should not have ticked"


def test_sequence_no_children(blackboard):
    seq = Sequence("empty", [])
    assert seq.tick(blackboard) == NodeStatus.SUCCESS


# ── Selector ────────────────────────────────────────────────────────

def test_selector_first_success(blackboard):
    a1 = SimpleAction("a1", NodeStatus.SUCCESS)
    a2 = SimpleAction("a2", NodeStatus.FAILURE)
    sel = Selector("sel", [a1, a2])
    assert sel.tick(blackboard) == NodeStatus.SUCCESS
    assert not a2.ticked, "second child should not have ticked"


def test_selector_all_fail(blackboard):
    sel = Selector("sel", [
        SimpleAction("a1", NodeStatus.FAILURE),
        SimpleAction("a2", NodeStatus.FAILURE),
    ])
    assert sel.tick(blackboard) == NodeStatus.FAILURE


# ── SequentialGroup ─────────────────────────────────────────────────

def test_sequential_group_meets_threshold(blackboard):
    seq = SequentialGroup("seq", [
        SimpleAction("a1", NodeStatus.SUCCESS),
        SimpleAction("a2", NodeStatus.SUCCESS),
        SimpleAction("a3", NodeStatus.SUCCESS),
        SimpleAction("a4", NodeStatus.FAILURE),
    ], min_success=3)
    assert seq.tick(blackboard) == NodeStatus.SUCCESS


def test_sequential_group_fails_threshold(blackboard):
    seq = SequentialGroup("seq", [
        SimpleAction("a1", NodeStatus.SUCCESS),
        SimpleAction("a2", NodeStatus.SUCCESS),
        SimpleAction("a3", NodeStatus.FAILURE),
        SimpleAction("a4", NodeStatus.FAILURE),
    ], min_success=3)
    assert seq.tick(blackboard) == NodeStatus.FAILURE
