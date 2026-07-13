# tests/unit/test_html_builder.py
from datetime import datetime
from websec_test.results.dashboard import HTMLBuilder

def test_html_builder_generates_html():
    builder = HTMLBuilder()
    report = {
        "target": "example.com",
        "start_time": "2023-10-27T10:00:00Z",
        "end_time": "2023-10-27T10:05:00Z",
        "duration_seconds": 300,
        "summary": {"total": 1, "pass": 1, "fail": 0, "warn": 0, "error": 0},
        "results": [
            {
                "status": "pass",
                "test_name": "Test1",
                "module": "Auth",
                "severity": "high",
                "expected": "yes",
                "actual": "yes"
            }
        ]
    }
    html = builder.build(report, "style.css", "script.js")
    assert "example.com" in html
    assert "style.css" in html
    assert "script.js" in html
    assert "Test1" in html
