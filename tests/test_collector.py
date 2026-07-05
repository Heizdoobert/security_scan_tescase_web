"""Tests for result collector."""
from websec_test.results.collector import ResultCollector
from websec_test.results.models import TestResult, TestStatus, Severity


def test_empty_collector():
    c = ResultCollector()
    assert c.total == 0
    assert c.by_status == {}


def test_add_single_result():
    c = ResultCollector()
    r = TestResult(module="headers", test_name="hsts", endpoint="/",
                   status=TestStatus.PASS, severity=Severity.LOW)
    c.add(r)
    assert c.total == 1
    assert c.by_status[TestStatus.PASS] == 1


def test_add_multiple_results():
    c = ResultCollector()
    results = [
        TestResult("headers", "hsts", TestStatus.PASS, Severity.LOW, "/"),
        TestResult("headers", "csp", TestStatus.FAIL, Severity.HIGH, "/"),
        TestResult("auth", "login", TestStatus.FAIL, Severity.CRITICAL, "/login"),
        TestResult("injection", "xss", TestStatus.ERROR, Severity.MEDIUM, "/search"),
    ]
    for r in results:
        c.add(r)
    assert c.total == 4
    assert c.by_status[TestStatus.PASS] == 1
    assert c.by_status[TestStatus.FAIL] == 2
    assert c.by_status[TestStatus.ERROR] == 1


def test_by_module_filters():
    c = ResultCollector()
    c.add(TestResult("headers", "hsts", TestStatus.PASS, Severity.LOW, "/"))
    c.add(TestResult("headers", "csp", TestStatus.FAIL, Severity.HIGH, "/"))
    c.add(TestResult("auth", "login", TestStatus.FAIL, Severity.CRITICAL, "/login"))
    header_results = [r for r in c.results if r.module == "headers"]
    assert len(header_results) == 2


def test_dedup_same_finding():
    c = ResultCollector()
    r1 = TestResult("injection", "sqli", TestStatus.FAIL, Severity.HIGH, "/search", evidence="test")
    r2 = TestResult("injection", "sqli", TestStatus.FAIL, Severity.HIGH, "/search", evidence="test")
    c.add(r1)
    c.add(r2)
    assert c.total == 1


def test_dedup_different_evidence():
    c = ResultCollector()
    r1 = TestResult("injection", "sqli", TestStatus.FAIL, Severity.HIGH, "/search", evidence="error 1")
    r2 = TestResult("injection", "sqli", TestStatus.FAIL, Severity.HIGH, "/search", evidence="error 2")
    c.add(r1)
    c.add(r2)
    assert c.total == 2
