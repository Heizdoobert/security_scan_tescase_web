# tests/unit/test_html_builder.py
import pytest
from websec_test.results.dashboard import HTMLBuilder

@pytest.mark.parametrize("status, fail_count, error_count, live", [
    ("pass", 0, 0, False),
    ("fail", 1, 0, False),
    ("error", 0, 1, False),
    ("pass", 0, 0, True),
])
def test_html_builder_generates_html(status, fail_count, error_count, live):
    builder = HTMLBuilder()
    report = {
        "target": "example.com",
        "start_time": "2023-10-27T10:00:00Z",
        "end_time": "2023-10-27T10:05:00Z",
        "duration_seconds": 300,
        "summary": {"total": 1, "pass": 1 if status == "pass" else 0, "fail": fail_count, "warn": 0, "error": error_count},
        "results": [
            {
                "status": status,
                "test_name": "Test1",
                "module": "Auth",
                "severity": "high",
                "expected": "yes",
                "actual": "yes"
            }
        ]
    }
    html = builder.build(report, "style.css", "script.js", live=live)
    assert "example.com" in html
    assert "style.css" in html
    assert "script.js" in html
    assert "Test1" in html
    
    if live:
        assert 'content="2"' in html
        assert "LIVE RUNNING" in html
    
    if status == "fail":
        assert "VULNERABLE" in html
    elif status == "error":
        assert "ERROR: The test could not be completed successfully." in html
