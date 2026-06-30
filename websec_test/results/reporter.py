"""Reporter — terminal, JSON, log output and dashboard for test results."""
import json
import webbrowser
from datetime import datetime
from pathlib import Path
from websec_test.results.collector import ResultCollector
from websec_test.results.models import TestStatus, Severity


def _derive_expect(result) -> str:
    """Derive expected behavior from test result status and severity."""
    if result.status == TestStatus.PASS:
        return "No vulnerability found — system is secure"
    elif result.status == TestStatus.FAIL:
        sev = result.severity.value if hasattr(result.severity, 'value') else str(result.severity)
        if "disable" in result.test_name or "delete" in result.test_name:
            return "Action should be blocked for unauthorized users"
        if "enum" in result.test_name or "brute" in result.test_name:
            return "Should not reveal user existence differences"
        if "hash" in result.test_name:
            return "Should use strong, salted, slow hashing algorithm"
        if "forgot" in result.test_name or "reset" in result.test_name:
            return "Password reset should require email/token verification"
        if "idor" in result.test_name or "private" in result.test_name:
            return "Private data should not be accessible by other users"
        if "admin" in result.test_name or "role" in result.test_name:
            return "Admin operations should be restricted to admin role"
        if "sql" in result.test_name or "inject" in result.test_name:
            return "Should reject malicious input"
        return f"Should reject or block this {sev} severity vulnerability"
    elif result.status == TestStatus.WARN:
        return "Should follow security best practices"
    else:
        return "Server should respond correctly"


class Reporter:
    """Formats test results as terminal output and JSON reports."""

    def __init__(self, collector: ResultCollector, target: str, duration: float = 0.0):
        self.collector = collector
        self.target = target
        self.duration = duration
        self._start_time = datetime.now()

    def _build_report(self) -> dict:
        return {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": self.duration,
            "start_time": self._start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "summary": {
                "total": self.collector.total,
                "pass": self.collector.by_status.get(TestStatus.PASS, 0),
                "fail": self.collector.by_status.get(TestStatus.FAIL, 0),
                "warn": self.collector.by_status.get(TestStatus.WARN, 0),
                "error": self.collector.by_status.get(TestStatus.ERROR, 0),
            },
            "results": [
                {
                    "module": r.module,
                    "test_name": r.test_name,
                    "status": r.status.value,
                    "severity": r.severity.value,
                    "endpoint": r.endpoint,
                    "expected": _derive_expect(r),
                    "actual": r.evidence,
                    "recommendation": r.recommendation,
                }
                for r in self.collector.results
            ],
        }

    def to_log(self, path: str = "log.txt") -> str:
        """Write plain-text log (no ANSI codes) to *path* and return it."""
        STATUS_LABELS = {
            TestStatus.PASS: "PASS",
            TestStatus.FAIL: "FAIL",
            TestStatus.WARN: "WARN",
            TestStatus.ERROR: "ERROR",
        }
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append(f"  Web Security Test — {self.target}")
        lines.append("=" * 60)
        lines.append(f"  Start: {self._start_time.isoformat()}")
        lines.append(f"  Modules: {len(set(r.module for r in self.collector.results))}")
        lines.append("")
        for r in self.collector.results:
            label = STATUS_LABELS.get(r.status, str(r.status.value))
            lines.append(f"  [{label}] {r.module}/{r.test_name}")
            lines.append(f"         Result: Expect: {_derive_expect(r)}")
            lines.append(f"                 Actual: {r.evidence[:120] if r.evidence else 'N/A'}")
            lines.append(f"         Endpoint: {r.endpoint}")
            if r.recommendation:
                lines.append(f"         Fix: {r.recommendation}")
            lines.append("")
        end_time = datetime.now()
        lines.append("-" * 60)
        lines.append(f"  End: {end_time.isoformat()}")
        lines.append(f"  Duration: {self.duration:.2f}s")
        lines.append(f"  Summary: {self.collector.total} total"
                     f"  |  PASS: {self.collector.by_status.get(TestStatus.PASS, 0)}"
                     f"  |  FAIL: {self.collector.by_status.get(TestStatus.FAIL, 0)}"
                     f"  |  WARN: {self.collector.by_status.get(TestStatus.WARN, 0)}"
                     f"  |  ERROR: {self.collector.by_status.get(TestStatus.ERROR, 0)}")
        lines.append("=" * 60)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return path

    def to_json(self, output_dir: str) -> str:
        """Write JSON report to output_dir and return the file path."""
        path = Path(output_dir) / f"websec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self._build_report(), f, indent=2)
        return str(path)

    def to_terminal(self):
        """Print colored summary to terminal with Start/End blocks and Expect/Actual."""
        BY_STATUS = {
            TestStatus.PASS: "\033[32mPASS\033[0m",
            TestStatus.FAIL: "\033[31mFAIL\033[0m",
            TestStatus.WARN: "\033[33mWARN\033[0m",
            TestStatus.ERROR: "\033[31mERROR\033[0m",
        }
        print(f"\n{'='*60}")
        print(f"  Web Security Test — {self.target}")
        print(f"{'='*60}")
        print(f"  Start: {self._start_time.isoformat()}")
        print(f"  Modules: {len(set(r.module for r in self.collector.results))}")
        print(f"{'='*60}\n")
        for r in self.collector.results:
            label = BY_STATUS.get(r.status, str(r.status.value))
            print(f"  [{label}] {r.module}/{r.test_name}")
            print(f"         Result: Expect: {_derive_expect(r)}")
            print(f"                 Actual: {r.evidence[:120] if r.evidence else 'N/A'}")
            print(f"         Endpoint: {r.endpoint}")
            if r.recommendation:
                print(f"         Fix: {r.recommendation}")
            print()
        end_time = datetime.now()
        print(f"{'-'*60}")
        print(f"  End: {end_time.isoformat()}")
        print(f"  Duration: {self.duration:.2f}s")
        print(f"  Summary: {self.collector.total} total"
              f"  |  PASS: {self.collector.by_status.get(TestStatus.PASS, 0)}"
              f"  |  FAIL: {self.collector.by_status.get(TestStatus.FAIL, 0)}"
              f"  |  WARN: {self.collector.by_status.get(TestStatus.WARN, 0)}"
              f"  |  ERROR: {self.collector.by_status.get(TestStatus.ERROR, 0)}")
        print(f"{'='*60}\n")

    def to_dashboard(self, output_dir: str = "./reports", open_browser: bool = False) -> str:
        """Generate an HTML dashboard and return the file path."""
        from websec_test.results.dashboard import Dashboard

        dash = Dashboard(self)
        path = dash.render(output_dir)
        if open_browser:
            webbrowser.open(f"file://{Path(path).resolve()}")
        return path
