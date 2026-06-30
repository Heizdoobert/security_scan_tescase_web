#!/usr/bin/env python3
"""Dependency auditor — scans package manifests for known CVEs."""
import sys, json, argparse
from websec_test.security.assessor import VulnerabilityAssessor

def main():
    parser = argparse.ArgumentParser(description="Dependency vulnerability auditor")
    parser.add_argument("--file", required=True, help="Path to package manifest")
    parser.add_argument("--severity", default="high", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()
    assessor = VulnerabilityAssessor(args.file, min_severity=args.severity)
    result = assessor.assess()
    if args.json:
        data = [{"cve_id": v.cve_id, "package": v.package, "installed": v.installed_version,
                 "fixed": v.fixed_version, "cvss": v.cvss_score} for v in result.vulnerabilities]
        output = json.dumps(data, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)
    else:
        for v in result.vulnerabilities:
            print(f"[{v.severity.upper()}] {v.cve_id} in {v.package} {v.installed_version}")
        print(f"Total: {result.count}")
    sys.exit(assessor.exit_code(result))

if __name__ == "__main__":
    main()
