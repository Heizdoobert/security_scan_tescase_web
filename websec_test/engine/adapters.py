from .nodes import NodeStatus
from .leaves import Action
from ..results.models import TestResult, TestStatus, Severity

class ModuleAdapter(Action):
    def __init__(self, name, module):
        super().__init__(name)
        self.module = module
    def do_tick(self, blackboard):
        client = blackboard.client
        target = blackboard.target
        try:
            endpoints = self.module.discover(client, target)
            results = self.module.test(client, target, endpoints)
            for r in (results or []):
                blackboard.add_result(r)
            has_failure = any(r.status in (TestStatus.FAIL, TestStatus.ERROR) for r in (results or []))
            return NodeStatus.FAILURE if has_failure else NodeStatus.SUCCESS
        except Exception as e:
            blackboard.add_result(TestResult(
                module=self.name,
                test_name="exception",
                status=TestStatus.ERROR,
                severity=Severity.HIGH,
                endpoint=target,
                evidence=str(e),
                recommendation="Check module compatibility",
            ))
            return NodeStatus.FAILURE


class CheckAdapter(Action):
    """Wraps a single check function into a BT Action node.

    The check_fn receives (client, target, blackboard) and returns
    a TestResult or None (skip).  The node adds the result to the
    blackboard and returns FAILURE when the check fails/errors.
    """

    def __init__(self, name, check_fn, module_name=""):
        super().__init__(name)
        self.check_fn = check_fn
        self.module_name = module_name or name

    def do_tick(self, blackboard):
        try:
            result = self.check_fn(blackboard.client, blackboard.target, blackboard)
        except Exception as e:
            blackboard.add_result(TestResult(
                module=self.module_name,
                test_name=self.name,
                status=TestStatus.ERROR,
                severity=Severity.HIGH,
                endpoint=blackboard.target,
                evidence=str(e),
                recommendation="Check function raised an exception",
            ))
            return NodeStatus.FAILURE
        if result is None:
            return NodeStatus.SUCCESS
        blackboard.add_result(result)
        if result.status in (TestStatus.FAIL, TestStatus.ERROR):
            return NodeStatus.FAILURE
        return NodeStatus.SUCCESS


class DiscoverAction(Action):
    """Wraps a discover function into a BT Action node.

    Calls discover_fn(client, target), stores the returned endpoints
    on the blackboard as '{name}_endpoints', and returns SUCCESS if
    endpoints were found, FAILURE otherwise.
    """

    def __init__(self, name, discover_fn):
        super().__init__(name)
        self.discover_fn = discover_fn

    def do_tick(self, blackboard):
        endpoints = self.discover_fn(blackboard.client, blackboard.target)
        key = f"{self.name}_endpoints"
        blackboard.set(key, endpoints or [])
        return NodeStatus.SUCCESS
