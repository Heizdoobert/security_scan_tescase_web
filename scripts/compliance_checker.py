#!/usr/bin/env python3
"""Thin CLI wrapper for websec_test.security.checker.ComplianceChecker."""
import sys, json, argparse
from websec_test.security.checker import ComplianceChecker

def main():
    parser = argparse.ArgumentParser(description="Security framework compliance checker")
    parser.add_argument("path", nargs="?", default=".", help="Project path")
    parser.add_argument("--framework", default="soc2", choices=["soc2", "pci_dss", "hipaa", "gdpr", "all"])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()
    checker = ComplianceChecker(args.path)
    result = checker.check(framework_filter=args.framework)
    if args.json:
        data = {"frameworks": [], "overall_score": result.overall_score}
        for fw in result.frameworks:
            data["frameworks"].append({
                "framework": fw.framework, "score_pct": fw.score_pct,
                "passed": fw.passed_count, "total": fw.total,
                "controls": [{"id": c.control_id, "passed": c.passed, "name": c.name,
                              "evidence": c.evidence} for c in fw.controls],
            })
        output = json.dumps(data, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)
    else:
        for fw in result.frameworks:
            print(f"[{fw.framework.upper()}] {fw.passed_count}/{fw.total} ({fw.score_pct:.0f}%)")
            for c in fw.controls:
                status = "PASS" if c.passed else "FAIL"
                print(f"  [{status}] {c.control_id}: {c.name}")
        print(f"Overall: {result.overall_score:.0f}% — Worst: {result.worst_framework}")
    sys.exit(checker.exit_code(result))

if __name__ == "__main__":
    main()
