# Script Consolidation Design Spec

## Overview
The `scripts/` directory currently contains 6 individual Python scripts that act as thin CLI wrappers around underlying security assessment classes (e.g., `SecurityScanner`, `VulnerabilityAssessor`). These scripts duplicate common CLI argument parsing (`--json`, `--output`, `--severity`) and result formatting logic. 

This spec outlines the plan to consolidate these redundant scripts into a single, shared utility script.

## Architecture & Components
We will implement **Approach A**: replacing the individual wrappers with a single CLI entry point using subcommands.

### 1. `scripts/cli.py`
A new script that serves as the unified entry point. It will use the standard library `argparse` module's `add_subparsers()` to handle different execution modes.

Subcommand Mapping:
- `cli.py scan` ➡️ Replaces `security_scanner.py` (Calls `SecurityScanner`)
- `cli.py assess` ➡️ Replaces `dependency_auditor.py`, `vulnerability_assessor.py` & `vulnerability_scanner.py` (Calls `VulnerabilityAssessor`)
- `cli.py check` ➡️ Replaces `compliance_checker.py` (Calls `ComplianceChecker`)
- `cli.py report` ➡️ Replaces `pentest_report_generator.py`

### 2. Output Handling
Output formatting will rely directly on the standard library's `json.dumps()` instead of building a custom formatter abstraction. This maintains simplicity while ensuring consistent JSON output for CI/CD pipelines.

### 3. Cleanup Phase
Once `cli.py` is fully implemented and tested, the following files will be deleted from the `scripts/` directory:
- `security_scanner.py`
- `dependency_auditor.py`
- `vulnerability_assessor.py`
- `vulnerability_scanner.py`
- `compliance_checker.py`
- `pentest_report_generator.py`

## Error Handling & Testing
- If a subcommand fails, the unified CLI script will capture the exception and return a standard non-zero exit code.
- Basic manual validation will be run against each subcommand to ensure the underlying classes are instantiated correctly.
