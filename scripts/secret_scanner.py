#!/usr/bin/env python3
"""Secret scanner CLI — detect secrets, API keys, tokens, and private keys.

Usage:
    python scripts/secret_scanner.py /path/to/project
    python scripts/secret_scanner.py /path/to/project --git-history
    python scripts/secret_scanner.py /path/to/project --min-entropy 4.0
    python scripts/secret_scanner.py /path/to/project --json --output secrets.json
    python scripts/secret_scanner.py /path/to/project -s critical
"""

import json
import sys
import argparse
from websec_test.security.secret_scanner import SecretScanner


def main():
    parser = argparse.ArgumentParser(
        description="Secret Scanner — detect secrets, API keys, tokens, and private keys")
    parser.add_argument("target", help="Project directory to scan")
    parser.add_argument("--git-history", action="store_true",
                        help="Also scan git history for committed secrets")
    parser.add_argument("--min-entropy", type=float, default=4.5,
                        help="Minimum Shannon entropy threshold (default: 4.5)")
    parser.add_argument("-s", "--severity",
                        choices=["low", "medium", "high", "critical"],
                        help="Minimum severity to report (default: all)")
    parser.add_argument("--exclude", action="append", default=[],
                        help="Additional file/directory patterns to exclude (repeatable)")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-o", "--output", help="Write results to file")
    args = parser.parse_args()

    scanner = SecretScanner(
        min_entropy=args.min_entropy,
        exclude=args.exclude if args.exclude else None,
        severity_filter=args.severity,
    )
    result = scanner.scan_all(args.target, git_history=args.git_history)

    if args.json or args.output:
        data = {
            "target": args.target,
            "files_scanned": result.files_scanned,
            "git_commits_scanned": result.git_commits_scanned,
            "secrets": [
                {
                    "path": s.path,
                    "line_number": s.line_number,
                    "secret_type": s.secret_type,
                    "match_preview": s.match_preview,
                    "severity": s.severity,
                    "context": s.context,
                    "recommendation": s.recommendation,
                    "entropy": s.entropy,
                    "source": s.source,
                }
                for s in result.secrets
            ],
            "summary": {
                "total": result.count,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
            },
            "exit_code": SecretScanner.exit_code(result),
        }
        output = json.dumps(data, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Report saved to {args.output}")
        else:
            print(output)
    else:
        if result.count == 0:
            print(f"[+] No secrets found in {args.target}")
            if args.git_history:
                print(f"    Files scanned: {result.files_scanned}")
                print(f"    Git commits scanned: {result.git_commits_scanned}")
        else:
            print(f"\nSecret Scan Report: {args.target}")
            print(f"{'=' * 60}")

            # Group by severity
            by_severity: dict = {}
            for s in result.secrets:
                by_severity.setdefault(s.severity, []).append(s)

            for sev in ["critical", "high", "medium"]:
                if sev not in by_severity:
                    continue
                print(f"\n  [{sev.upper()}]")
                print(f"  {'-' * 56}")
                for s in by_severity[sev]:
                    source_tag = f" [{s.source}]" if s.source != "pattern" else ""
                    print(f"    {s.secret_type}{source_tag}")
                    print(f"      File: {s.path}:{s.line_number}")
                    print(f"      Match: {s.match_preview}")
                    if s.entropy > 0:
                        print(f"      Entropy: {s.entropy:.2f}")
                    print(f"      Fix: {s.recommendation}")
                    print()

            print(f"{'=' * 60}")
            print(f"  Summary: {result.count} secrets found"
                  f"  |  Critical: {result.critical_count}"
                  f"  |  High: {result.high_count}"
                  f"  |  Medium: {result.medium_count}")
            if args.git_history:
                print(f"  Files scanned: {result.files_scanned}"
                      f"  |  Git commits scanned: {result.git_commits_scanned}")
            print(f"{'=' * 60}")

    sys.exit(SecretScanner.exit_code(result))


if __name__ == "__main__":
    main()
