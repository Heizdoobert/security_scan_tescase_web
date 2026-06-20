#!/usr/bin/env python3
"""SAST security scanner — standalone CLI.

Usage:
    python scripts/security_scanner.py /path/to/project
    python scripts/security_scanner.py /path/to/project --severity high
    python scripts/security_scanner.py /path/to/project --json --output report.json
"""

import json
import sys
import argparse
from websec_test.security.scanner import SecurityScanner


def main():
    parser = argparse.ArgumentParser(description="SAST Security Scanner")
    parser.add_argument("target", help="Directory or file to scan")
    parser.add_argument("-s", "--severity", default="low",
                        choices=["critical", "high", "medium", "low"],
                        help="Minimum severity to report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show files as scanned")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-o", "--output", help="Write results to file")
    args = parser.parse_args()

    scanner = SecurityScanner(args.target, min_severity=args.severity)
    findings = scanner.scan()

    if args.json or args.output:
        data = {
            "target": args.target,
            "severity_filter": args.severity,
            "findings": [
                {"file": f.file_path, "line": f.line_number,
                 "category": f.category, "severity": f.severity,
                 "evidence": f.evidence, "recommendation": f.recommendation}
                for f in findings
            ],
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.severity == "critical"),
                "high": sum(1 for f in findings if f.severity == "high"),
                "medium": sum(1 for f in findings if f.severity == "medium"),
                "low": sum(1 for f in findings if f.severity == "low"),
            },
            "exit_code": SecurityScanner.exit_code(findings),
        }
        output = json.dumps(data, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Report saved to {args.output}")
        else:
            print(output)
    else:
        if not findings:
            print(f"[+] No findings in {args.target}")
        else:
            for f in findings:
                severity_label = f.severity.upper()
                print(f"  [{severity_label}] {f.file_path}:{f.line_number}")
                print(f"           {f.category}: {f.evidence[:100]}")
            print(f"\nSummary: {len(findings)} total"
                  f"  |  Critical: {sum(1 for x in findings if x.severity == 'critical')}"
                  f"  |  High: {sum(1 for x in findings if x.severity == 'high')}"
                  f"  |  Med: {sum(1 for x in findings if x.severity == 'medium')}"
                  f"  |  Low: {sum(1 for x in findings if x.severity == 'low')}")

    sys.exit(SecurityScanner.exit_code(findings))


if __name__ == "__main__":
    main()
