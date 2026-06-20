#!/usr/bin/env python3
"""Compliance framework checker — standalone CLI.

Usage:
    python scripts/compliance_checker.py /path/to/project
    python scripts/compliance_checker.py /path/to/project --framework soc2
    python scripts/compliance_checker.py /path/to/project --json --output compliance.json
"""

import json
import sys
import argparse
from websec_test.security.checker import ComplianceChecker


def main():
    parser = argparse.ArgumentParser(description="Compliance Framework Checker")
    parser.add_argument("target", help="Project directory to check")
    parser.add_argument("-f", "--framework", default="all",
                        choices=["soc2", "pci-dss", "hipaa", "gdpr", "all"],
                        help="Compliance framework to check")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show checks as they run")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-o", "--output", help="Write results to file")
    args = parser.parse_args()

    # Map CLI framework names to internal names
    fw_map = {"soc2": "soc2", "pci-dss": "pci_dss", "hipaa": "hipaa", "gdpr": "gdpr", "all": "all"}
    internal_fw = fw_map.get(args.framework, "all")

    checker = ComplianceChecker(args.target)
    result = checker.check(framework_filter=internal_fw)

    if args.json or args.output:
        data = {
            "target": args.target,
            "overall_score": round(result.overall_score, 1),
            "frameworks": [
                {
                    "framework": f.framework,
                    "score": round(f.score_pct, 1),
                    "passed": f.passed_count,
                    "total": f.total,
                    "controls": [
                        {"id": c.control_id, "name": c.name,
                         "passed": c.passed, "evidence": c.evidence}
                        for c in f.controls
                    ],
                }
                for f in result.frameworks
            ],
            "exit_code": ComplianceChecker.exit_code(result),
        }
        output = json.dumps(data, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Report saved to {args.output}")
        else:
            print(output)
    else:
        for fw in result.frameworks:
            print(f"\n{'='*50}")
            print(f"  {fw.framework.upper()} — {fw.score_pct:.0f}% compliant ({fw.passed_count}/{fw.total})")
            print(f"{'='*50}")
            for c in fw.controls:
                status = "PASS" if c.passed else "FAIL"
                print(f"  [{status}] {c.control_id}: {c.name}")
                if args.verbose or not c.passed:
                    print(f"         Evidence: {c.evidence[:120]}")

        overall = result.overall_score
        print(f"\n{'='*50}")
        print(f"  Overall compliance: {overall:.0f}%"
              f"  |  Worst framework: {result.worst_framework}")
        print(f"{'='*50}")

    sys.exit(ComplianceChecker.exit_code(result))


if __name__ == "__main__":
    main()
