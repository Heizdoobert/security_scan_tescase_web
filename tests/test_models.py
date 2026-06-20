"""Tests for result models."""
from websec_test.results.models import TestResult, TestStatus, Severity


def test_testresult_defaults():
    r = TestResult(module="headers", test_name="check_hsts", endpoint="/")
    assert r.status == TestStatus.WARN
    assert r.severity == Severity.MEDIUM
    assert r.evidence == ""
    assert r.recommendation == ""


def test_testresult_full():
    r = TestResult(
        module="auth",
        test_name="sql_login_bypass",
        status=TestStatus.FAIL,
        severity=Severity.CRITICAL,
        endpoint="/login",
        evidence="200 OK with admin access",
        recommendation="Sanitize all login inputs",
    )
    assert r.status == TestStatus.FAIL
    assert r.severity == Severity.CRITICAL
    assert r.endpoint == "/login"


def test_status_values():
    assert TestStatus.PASS.value == "pass"
    assert TestStatus.FAIL.value == "fail"
    assert TestStatus.WARN.value == "warn"
    assert TestStatus.ERROR.value == "error"


def test_severity_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"
