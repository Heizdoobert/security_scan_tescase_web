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

class Condition(Node):
    def __init__(self, name, predicate):
        super().__init__(name)
        self.predicate = predicate
    def tick(self, blackboard):
        return NodeStatus.SUCCESS if self.predicate(blackboard) else NodeStatus.FAILURE
