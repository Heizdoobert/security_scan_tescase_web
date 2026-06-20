"""Result models for security test outputs."""
from dataclasses import dataclass, field
from enum import Enum


class TestStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TestResult:
    module: str
    test_name: str
    status: TestStatus = TestStatus.WARN
    severity: Severity = Severity.MEDIUM
    endpoint: str = ""
    evidence: str = ""
    recommendation: str = ""
