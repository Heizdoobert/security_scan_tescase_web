#!/usr/bin/env python3
"""Threat modeler — STRIDE classification and DREAD scoring for DFD elements.

Usage:
    python scripts/threat_modeler.py /path/to/project
    python scripts/threat_modeler.py /path/to/project --element-type process
    python scripts/threat_modeler.py /path/to/project --json --output threats.json
"""

import json
import sys
import argparse
from websec_test.security.threat_model import ThreatModeler, ELEMENT_DESCRIPTIONS


def main():
    parser = argparse.ArgumentParser(
        description="Threat Modeler — STRIDE + DREAD Analysis")
    parser.add_argument("target", help="Project directory to analyze")
    parser.add_argument("-e", "--element-type", action="append",
                        choices=["external-entity", "process",
                                 "data-store", "data-flow"],
                        help="DFD element type to analyze (repeatable, default: all)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show element descriptions")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-o", "--output", help="Write results to file")
    args = parser.parse_args()

    result = ThreatModeler.assess_all(args.target, args.element_type)

    if args.json or args.output:
        data = {
            "target": args.target,
            "element_types": args.element_type or list(ThreatModeler.VALID_ELEMENT_TYPES),
            "threats": [
                {
                    "element_type": t.element_type,
                    "element_name": t.element_name,
                    "stride_category": t.stride_category,
                    "threat_description": t.threat_description,
                    "dread_score": t.dread_score,
                    "severity": t.severity,
                    "recommendation": t.recommendation,
                }
                for t in result.threats
            ],
            "summary": {
                "total": result.count,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
            },
            "exit_code": ThreatModeler.exit_code(result),
        }
        output = json.dumps(data, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Report saved to {args.output}")
        else:
            print(output)
    else:
        if not result.threats:
            print(f"[+] No threats identified for {args.target}")
        else:
            # Group threats by element type
            by_element: dict = {}
            for t in result.threats:
                by_element.setdefault(t.element_type, []).append(t)

            for etype, threats in by_element.items():
                if args.verbose:
                    desc = ELEMENT_DESCRIPTIONS.get(etype, etype)
                    print(f"\n{'=' * 60}")
                    print(f"  {desc}")
                    print(f"{'=' * 60}")
                else:
                    print(f"\n-- {etype.upper()} --")

                for t in threats:
                    dread_action = ThreatModeler.dread_label(t.dread_score)
                    print(f"\n  [{t.severity.upper()}] {t.stride_category}"
                          f"  (DREAD: {t.dread_score:.1f}/10)")
                    print(f"         {t.threat_description}")
                    print(f"         Fix: {t.recommendation}")
                    print(f"         {dread_action}")

            print(f"\n{'-' * 60}")
            print(f"  Summary: {result.count} threats total"
                  f"  |  Critical: {result.critical_count}"
                  f"  |  High: {result.high_count}"
                  f"  |  Medium: {result.medium_count}")
            print(f"{'-' * 60}")

    sys.exit(ThreatModeler.exit_code(result))


if __name__ == "__main__":
    main()
