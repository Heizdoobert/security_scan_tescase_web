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
