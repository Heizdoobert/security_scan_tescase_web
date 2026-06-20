# Design: CI Security Gate

**Date:** 2026-06-20
**Status:** Draft

## Problem Statement

The WebSec Test project has SAST scanning, dependency assessment, and compliance checking tools but no automated CI pipeline to enforce them. Security findings are only discovered when someone remembers to run the scripts manually. PRs can be merged with critical vulnerabilities, hardcoded secrets, or compliance gaps.

## Approach

Create a GitHub Actions workflow (`.github/workflows/security-scan.yml`) with two jobs:

1. **`security-gate`** — runs on every PR to `main`/`develop`. Fails the pipeline on exit code 2 (critical findings). Three sequential steps with fail-fast semantics.
2. **`nightly-audit`** — scheduled daily on `main`. Runs comprehensive checks across all frameworks. Reports are uploaded as artifacts.

This matches the Senior SecOps Engineer skill's Workflow 2 pattern: fast PR gates plus periodic deep scans.

## Workflow Design

### File: `.github/workflows/security-scan.yml`

### Job 1: `security-gate`

```yaml
name: "security-scan"

on:
  pull_request:
    branches: [main, develop]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: install-deps
        run: pip install -r requirements.txt
      - name: security-scanner
        run: python scripts/security_scanner.py . --severity high
      - name: vulnerability-assessment
        run: python scripts/vulnerability_assessor.py . --severity critical
      - name: compliance-check
        run: python scripts/compliance_checker.py . --framework soc2
```

**Trigger:** `pull_request` to `main` and `develop`.

**Fail-fast behavior:** Each step that returns exit code 2 stops the pipeline immediately. Steps that return exit code 1 (high warnings) proceed — PR author sees a warning but is not blocked.

| Step | Severity Filter | Fails on | Status on pass |
|------|----------------|----------|----------------|
| security-scanner | `--severity high` | Critical (exit 2) | Green |
| vulnerability-assessment | `--severity critical` | Critical (exit 2) | Green |
| compliance-check | SOC 2 only | Critical gaps (<50%) | Green |

### Job 2: `nightly-audit`

```yaml
  nightly-audit:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: install-deps
        run: pip install -r requirements.txt
      - name: full-security-scan
        run: python scripts/security_scanner.py . --severity medium --json --output security.json
      - name: full-vulnerability-scan
        run: python scripts/vulnerability_assessor.py . --severity high --json --output vulns.json
      - name: full-compliance-audit
        run: python scripts/compliance_checker.py . --framework all --json --output compliance.json
      - name: upload-reports
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            security.json
            vulns.json
            compliance.json
```

**Trigger:** Schedule (daily, e.g., midnight UTC).

**Non-blocking:** This job never fails the build. Reports are stored as artifacts for the security team to review.

## Error Handling

- **Exit code 0:** Step passes. Green checkmark.
- **Exit code 1:** Step passes with warnings. Yellow indicator. PR can merge.
- **Exit code 2:** Step fails. Red X. Pipeline stops. PR blocked until resolved.
- **Any non-zero unexpected exit:** Pipeline fails. Treat as infrastructure error.

## Testing Strategy

- **Dry-run locally:** Test the workflow with `act` (GitHub Actions local runner) if available
- **Verification:** Create a test PR with a known vulnerability and confirm the gate blocks it
- **Edge case:** Empty project (no files to scan) — all tools should return exit code 0

## Out of Scope

- `scripts/threat_modeler.py` (Phase 3)
- `scripts/secret_scanner.py` (Phase 4)
- Pre-commit hooks (recommended in the reference docs but not implemented here)
- PR comment posting (nice-to-have for future)

## References

- [GitHub Actions workflow syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)
- Senior SecOps Engineer skill — Workflow 2: CI/CD Security Gate
