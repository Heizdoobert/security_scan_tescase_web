#!/usr/bin/env python3
"""Unified CLI entry point for websec_test security tools."""
import sys
import json
import argparse
from websec_test.security.scanner import SecurityScanner
from websec_test.security.assessor import VulnerabilityAssessor
from websec_test.security.checker import ComplianceChecker

def main():
    parser = argparse.ArgumentParser(description="WebSec Test Security Tools CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Subcommand: scan
    scan_parser = subparsers.add_parser("scan", help="Run SAST security scanner")
    scan_parser.add_argument("path", nargs="?", default=".", help="Project path")
    scan_parser.add_argument("--severity", default="high", choices=["low", "medium", "high", "critical"])
    scan_parser.add_argument("--json", action="store_true", help="JSON output")
    scan_parser.add_argument("--output", help="Output file path")

    # Subcommand: assess
    assess_parser = subparsers.add_parser("assess", help="Run Vulnerability Assessor")
    # Subcommand: check
    check_parser = subparsers.add_parser("check", help="Run Compliance Checker")
    # Subcommand: report
    report_parser = subparsers.add_parser("report", help="Generate pentest reports")

    args = parser.parse_args()
    
    if args.command == "scan":
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
        
    elif args.command == "assess":
        assessor = VulnerabilityAssessor()
        findings = assessor.assess()
        print(f"Assessed {len(findings)} vulnerabilities")
        sys.exit(assessor.exit_code(findings))
        
    elif args.command == "check":
        checker = ComplianceChecker()
        findings = checker.check()
        print(f"Checked compliance: {len(findings)} findings")
        sys.exit(checker.exit_code(findings))
        
    elif args.command == "report":
        print("Generating pentest report...")
        sys.exit(0)

if __name__ == "__main__":
    main()
