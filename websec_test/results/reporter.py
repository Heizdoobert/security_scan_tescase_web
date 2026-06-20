"""Reporter — terminal and JSON output for test results."""
import json
from datetime import datetime
from pathlib import Path
from websec_test.results.collector import ResultCollector
from websec_test.results.models import TestStatus, Severity


class Reporter:
    """Formats test results as terminal output and JSON reports."""

    def __init__(self, collector: ResultCollector, target: str, duration: float = 0.0):
        self.collector = collector
        self.target = target
        self.duration = duration

    def _build_report(self) -> dict:
        return {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": self.duration,
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
                    "evidence": r.evidence,
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
        lines.append("")
        for r in self.collector.results:
            label = STATUS_LABELS.get(r.status, str(r.status.value))
            lines.append(f"  [{label}] {r.module}/{r.test_name}")
            lines.append(f"         Endpoint: {r.endpoint}")
            if r.evidence:
                lines.append(f"         Evidence: {r.evidence[:100]}")
            if r.recommendation:
                lines.append(f"         Fix: {r.recommendation}")
            lines.append("")
        lines.append("-" * 60)
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
        """Print colored summary to terminal."""
        BY_STATUS = {
            TestStatus.PASS: "\033[32mPASS\033[0m",
            TestStatus.FAIL: "\033[31mFAIL\033[0m",
            TestStatus.WARN: "\033[33mWARN\033[0m",
            TestStatus.ERROR: "\033[31mERROR\033[0m",
        }
        print(f"\n{'='*60}")
        print(f"  Web Security Test — {self.target}")
        print(f"{'='*60}\n")
        for r in self.collector.results:
            label = BY_STATUS.get(r.status, str(r.status.value))
            print(f"  [{label}] {r.module}/{r.test_name}")
            print(f"         Endpoint: {r.endpoint}")
            if r.evidence:
                print(f"         Evidence: {r.evidence[:100]}")
            if r.recommendation:
                print(f"         Fix: {r.recommendation}")
            print()
        print(f"{'-'*60}")
        print(f"  Summary: {self.collector.total} total"
              f"  |  PASS: {self.collector.by_status.get(TestStatus.PASS, 0)}"
              f"  |  FAIL: {self.collector.by_status.get(TestStatus.FAIL, 0)}"
              f"  |  WARN: {self.collector.by_status.get(TestStatus.WARN, 0)}"
              f"  |  ERROR: {self.collector.by_status.get(TestStatus.ERROR, 0)}")
        print(f"{'='*60}\n")
