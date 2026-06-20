# Implementation Plan: CI Security Gate

**Based on:** `docs/superpowers/specs/2026-06-20-ci-security-gate-design.md`
**Date:** 2026-06-20

## Task 1: Create `.github/workflows/security-scan.yml`

Create the GitHub Actions workflow file with two jobs.

### File
`D:\testcase_web\.github\workflows\security-scan.yml`

### Job 1: `security-gate`
- Trigger: `pull_request` to `main` and `develop`
- Runs-on: `ubuntu-latest`
- Steps (sequential, fail-fast on exit code 2):
  1. `actions/checkout@v4`
  2. `actions/setup-python@v5` with `python-version: '3.11'`
  3. `pip install -r requirements.txt`
  4. `python scripts/security_scanner.py . --severity high`
  5. `python scripts/vulnerability_assessor.py . --severity critical`
  6. `python scripts/compliance_checker.py . --framework soc2`

### Job 2: `nightly-audit`
- Trigger: `schedule` (daily cron)
- Condition: `if: github.event_name == 'schedule'`
- Runs-on: `ubuntu-latest`
- Steps:
  1-3. Same checkout + setup + deps
  4. `python scripts/security_scanner.py . --severity medium --json --output security.json`
  5. `python scripts/vulnerability_assessor.py . --severity high --json --output vulns.json`
  6. `python scripts/compliance_checker.py . --framework all --json --output compliance.json`
  7. `actions/upload-artifact@v4` with name `security-reports` and all three JSON files

### Verification
- Validate YAML syntax (e.g., `python -c "import yaml; yaml.safe_load(open(...))"`)
- Confirm file is in `.github/workflows/` directory (GitHub Actions requirement)
