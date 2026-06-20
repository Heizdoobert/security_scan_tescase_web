from enum import Enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

class NodeStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    RUNNING = "running"

class Blackboard:
    def __init__(self, client, target):
        self.client = client
        self.target = target
        self.results = []
        self._store = {}
    def add_result(self, result):
        self.results.append(result)
    def get(self, key, default=None):
        return self._store.get(key, default)
    def set(self, key, value):
        self._store[key] = value

class Node(ABC):
    def __init__(self, name):
        self.name = name
    @abstractmethod
    def tick(self, blackboard):
        pass

class Sequence(Node):
    def __init__(self, name, children=None):
        super().__init__(name)
        self.children = children or []
    def tick(self, blackboard):
        for child in self.children:
            status = child.tick(blackboard)
            if status != NodeStatus.SUCCESS:
                return status
        return NodeStatus.SUCCESS

class Selector(Node):
    def __init__(self, name, children=None):
        super().__init__(name)
        self.children = children or []
    def tick(self, blackboard):
        for child in self.children:
            status = child.tick(blackboard)
            if status == NodeStatus.SUCCESS:
                return NodeStatus.SUCCESS
        return NodeStatus.FAILURE

class Parallel(Node):
    """Run children sequentially, requiring a minimum number of successes.

    Note: Children are executed SEQUENTIALLY in the current implementation,
    not concurrently. The name reflects *semantic* parallelism — independent
    checks that don't depend on each other's results.

    ``min_success`` is the count of successful children required for the
    overall node to return SUCCESS. If fewer children succeed, returns FAILURE.
    """

    def __init__(self, name, children=None, min_success=1):
        super().__init__(name)
        self.children = children or []
        self.min_success = min_success
    def tick(self, blackboard):
        success_count = 0
        for child in self.children:
            status = child.tick(blackboard)
            if status == NodeStatus.SUCCESS:
                success_count += 1
        return NodeStatus.SUCCESS if success_count >= self.min_success else NodeStatus.FAILURE
