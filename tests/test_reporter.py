"""Tests for reporter."""
import json
import tempfile
from pathlib import Path
from websec_test.results.reporter import Reporter
from websec_test.results.collector import ResultCollector
from websec_test.results.models import TestResult, TestStatus, Severity


def _collector_with_results():
    c = ResultCollector()
    c.add(TestResult("headers", "hsts", TestStatus.PASS, Severity.LOW, "/"))
    c.add(TestResult("headers", "csp", TestStatus.FAIL, Severity.HIGH, "/",
                     evidence="missing header",
                     recommendation="Add Content-Security-Policy header"))
    return c


def test_json_output_contains_summary():
    c = _collector_with_results()
    reporter = Reporter(c, target="http://test.local")
    with tempfile.TemporaryDirectory() as tmp:
        path = reporter.to_json(tmp)
        with open(path) as f:
            data = json.load(f)
        assert data["target"] == "http://test.local"
        assert data["summary"]["total"] == 2
        assert data["summary"]["pass"] == 1
        assert data["summary"]["fail"] == 1


def test_json_output_contains_results():
    c = _collector_with_results()
    reporter = Reporter(c, target="http://test.local")
    with tempfile.TemporaryDirectory() as tmp:
        path = reporter.to_json(tmp)
        with open(path) as f:
            data = json.load(f)
        assert len(data["results"]) == 2
        assert data["results"][0]["module"] == "headers"


def test_json_has_timestamp():
    c = _collector_with_results()
    reporter = Reporter(c, target="http://test.local")
    with tempfile.TemporaryDirectory() as tmp:
        path = reporter.to_json(tmp)
        assert Path(path).stat().st_size > 0
        assert "websec_report_" in path


def test_log_output_contains_results():
    c = _collector_with_results()
    reporter = Reporter(c, target="http://test.local")
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "test.log"
        result = reporter.to_log(str(log_path))
        assert Path(result).exists()
        content = log_path.read_text()
        assert "PASS" in content
        assert "FAIL" in content
        assert "hsts" in content
        assert "Summary: 2 total" in content
        assert "missing header" in content


def test_terminal_output_basic(capsys):
    c = _collector_with_results()
    reporter = Reporter(c, target="http://test.local")
    reporter.to_terminal()
    captured = capsys.readouterr()
    assert "PASS" in captured.out or "FAIL" in captured.out
