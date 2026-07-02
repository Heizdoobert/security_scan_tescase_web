---
name: websec-test
description: "Use when working in this repository on the WebSec Test project, the behavior-tree-based web security testing CLI, the security scanning scripts, or the Vietnamese internship report DOCX artifacts."
---

# WebSec Test Skill

Use this skill as the project memory for the repository.

## Project Facts
- The repo is a Python web security testing tool called WebSec Test.
- The main scanner uses a Behavior Tree engine for composable security checks.
- The codebase includes authentication, authorization, injection, and configuration test modules.
- There are standalone SecOps-style scripts for SAST, dependency checks, compliance checks, and related security workflows.
- The repo also contains Vietnamese internship report DOCX generation artifacts that should preserve their existing formatting constraints.

## Working Rules
- Prefer small, targeted changes that fit the existing module layout.
- Keep behavior-tree and module-adapter patterns intact unless a change explicitly requires structural refactoring.
- When editing tests, preserve the existing `responses`-based mocking style and the module-level assertions already used in the suite.
- For report-generation work, keep the existing `generate_final.py` approach, short helper names, and explicit East-Asia font setup for Vietnamese diacritics.
- Do not widen scope to unrelated modules or reports unless the requested change needs it.

## Report Generation Notes
- The generated internship report output already exists in the repository artifacts.
- Preserve A4 layout, Times New Roman, and the documented margin settings when touching DOCX generation.
- Keep helper names short when working around JSON/tooling size limits.
- Set East-Asia fonts explicitly on every run when generating Vietnamese text.
