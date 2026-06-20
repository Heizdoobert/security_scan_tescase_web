"""Result collector — aggregate results across test modules."""
from collections import defaultdict
from websec_test.results.models import TestResult, TestStatus, Severity


class ResultCollector:
    """Accumulates TestResult instances and provides summary statistics."""

    def __init__(self):
        self.results: list[TestResult] = []
        self._seen: set[tuple] = set()

    def add(self, result: TestResult):
        key = (result.module, result.test_name, result.endpoint, result.evidence)
        if key in self._seen:
            return
        self._seen.add(key)
        self.results.append(result)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def by_status(self) -> dict[TestStatus, int]:
        counts = defaultdict(int)
        for r in self.results:
            counts[r.status] += 1
        return dict(counts)

    @property
    def by_severity(self) -> dict[Severity, int]:
        counts = defaultdict(int)
        for r in self.results:
            counts[r.severity] += 1
        return dict(counts)

    def by_module(self, module_name: str) -> dict[str, int]:
        counts = {"pass": 0, "fail": 0, "warn": 0, "error": 0}
        for r in self.results:
            if r.module == module_name:
                counts[r.status.value] += 1
        return counts
