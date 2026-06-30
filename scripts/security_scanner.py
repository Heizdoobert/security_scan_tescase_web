#!/usr/bin/env python3
"""Thin CLI wrapper for websec_test.security.scanner.SecurityScanner."""
import sys, json, argparse
from websec_test.security.scanner import SecurityScanner

def main():
    parser = argparse.ArgumentParser(description="SAST security scanner")
    parser.add_argument("path", nargs="?", default=".", help="Project path")
    parser.add_argument("--severity", default="high", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()
    scanner = SecurityScanner(args.path, min_severity=args.severity)
    findings = scanner.scan()
    if args.json:
        data = [{"file": f.file_path, "line": f.line_number, "severity": f.severity,
                 "category": f.category, "evidence": f.evidence} for f in findings]
        output = json.dumps(data, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)
    else:
        for f in findings:
            print(f"[{f.severity.upper()}] {f.file_path}:{f.line_number}  {f.category}: {f.evidence[:100]}")
        print(f"Summary: {len(findings)} findings")
    sys.exit(scanner.exit_code(findings))

if __name__ == "__main__":
    main()
