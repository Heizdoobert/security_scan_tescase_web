import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from .nodes import Node, NodeStatus, Blackboard

class Decorator(Node):
    def __init__(self, name, child):
        super().__init__(name)
        self.child = child

class Retry(Decorator):
    def __init__(self, name, child, max_attempts=3, delay=0):
        super().__init__(name, child)
        self.max_attempts = max_attempts
        self.delay = delay
    def tick(self, blackboard):
        for attempt in range(self.max_attempts):
            status = self.child.tick(blackboard)
            if status == NodeStatus.SUCCESS:
                return NodeStatus.SUCCESS
            if self.delay and attempt < self.max_attempts - 1:
                time.sleep(self.delay)
        return NodeStatus.FAILURE

class Timeout(Decorator):
    def __init__(self, name, child, max_seconds=10):
        super().__init__(name, child)
        self.max_seconds = max_seconds
        self._executor = ThreadPoolExecutor(max_workers=1)
    def tick(self, blackboard):
        future = self._executor.submit(self.child.tick, blackboard)
        try:
            return future.result(timeout=self.max_seconds)
        except FuturesTimeout:
            return NodeStatus.FAILURE
    def __del__(self):
        self._executor.shutdown(wait=False)

class Invert(Decorator):
    def __init__(self, name, child):
        super().__init__(name, child)
    def tick(self, blackboard):
        status = self.child.tick(blackboard)
        if status == NodeStatus.SUCCESS:
            return NodeStatus.FAILURE
        elif status == NodeStatus.FAILURE:
            return NodeStatus.SUCCESS
        return status

class Cooldown(Decorator):
    def __init__(self, name, child, min_interval=0):
        super().__init__(name, child)
        self.min_interval = min_interval
        self._last_tick = 0
    def tick(self, blackboard):
        now = time.time()
        if now - self._last_tick < self.min_interval:
            return NodeStatus.SUCCESS
        self._last_tick = now
        return self.child.tick(blackboard)

class Log(Decorator):
    def __init__(self, name, child, label=""):
        super().__init__(name, child)
        self.label = label or name
    def tick(self, blackboard):
        start = time.time()
        status = self.child.tick(blackboard)
        elapsed = time.time() - start
        print(f"[{self.label}] {status.value} ({elapsed:.3f}s)")
        return status
