from .nodes import Node, NodeStatus, Blackboard
from abc import abstractmethod

class Action(Node):
    @abstractmethod
    def do_tick(self, blackboard):
        pass
    def tick(self, blackboard):
        try:
            return self.do_tick(blackboard)
        except Exception:
            return NodeStatus.FAILURE


class Condition(Action):
    def __init__(self, name, fn):
        super().__init__(name)
        self.fn = fn
    def do_tick(self, blackboard):
        return NodeStatus.SUCCESS if self.fn(blackboard) else NodeStatus.FAILURE
