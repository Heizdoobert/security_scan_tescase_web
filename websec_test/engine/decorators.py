import time
import threading
from .nodes import Node, NodeStatus


class Decorator(Node):
    def __init__(self, name, child):
        super().__init__(name)
        self.child = child
    def tick(self, blackboard):
        return self.child.tick(blackboard)


class Retry(Decorator):
    def __init__(self, name, child, max_retries=1, delay=0):
        super().__init__(name, child)
        self.max_retries = max_retries
        self.delay = delay
    def tick(self, blackboard):
        for attempt in range(self.max_retries + 1):
            status = self.child.tick(blackboard)
            if status == NodeStatus.SUCCESS:
                return NodeStatus.SUCCESS
            if self.delay and attempt < self.max_retries:
                time.sleep(self.delay)
        return NodeStatus.FAILURE


class Timeout(Decorator):
    def __init__(self, name, child, timeout=30):
        super().__init__(name, child)
        self.timeout = timeout
    def tick(self, blackboard):
        result = [NodeStatus.FAILURE]
        done = threading.Event()
        def run():
            try:
                result[0] = self.child.tick(blackboard)
            except Exception:
                result[0] = NodeStatus.FAILURE
            finally:
                done.set()
        t = threading.Thread(target=run, daemon=True)
        t.start()
        done.wait(self.timeout)
        return result[0]


class Invert(Decorator):
    def __init__(self, name, child):
        super().__init__(name, child)
    def tick(self, blackboard):
        status = self.child.tick(blackboard)
        if status == NodeStatus.SUCCESS:
            return NodeStatus.FAILURE
        if status == NodeStatus.FAILURE:
            return NodeStatus.SUCCESS
        return status
