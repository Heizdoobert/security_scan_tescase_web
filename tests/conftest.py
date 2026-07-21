import json, os
from datetime import datetime

REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")


def pytest_terminal_summary(terminalreporter):
    passed = terminalreporter.stats.get("passed", [])
    failed = terminalreporter.stats.get("failed", [])
    errors = terminalreporter.stats.get("error", [])
    skipped = terminalreporter.stats.get("skipped", [])
    results = []
    for items, status in [(passed, "PASS"), (failed, "FAIL"), (errors, "ERROR"), (skipped, "SKIP")]:
        for item in items:
            results.append({"test": item.nodeid.split("::")[-1], "status": status})
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORT_DIR, f"pentestgpt_summary_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"total": len(results), "passed": len(passed), "failed": len(failed), "error": len(errors), "results": results}, f, indent=2)
    terminalreporter.write_sep("=", f"Summary report: {path}")
