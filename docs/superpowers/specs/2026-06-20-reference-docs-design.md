# Design: Security Reference Documentation

**Date:** 2026-06-20
**Status:** Draft

## Problem Statement

The WebSec Test project has a comprehensive SAST scanner, dependency assessor, and compliance checker — but no formal reference documentation that explains *what* each check tests, *why* it matters, or *how* it maps to security standards and compliance frameworks. Engineers running the tool need to understand findings. Auditors need to verify control coverage. Both currently have to reverse-engineer the code.

## Approach

Create 4 lightweight reference documents in `references/` that serve as the **source of truth** for what the tool checks and why. Each doc follows a consistent format and includes a **Tool Mapping** section that explicitly links each control or standard to the automated check (or marks it as "manual review").

## Document Structure

All 4 documents share this layout:

```markdown
# Title

> One-sentence purpose statement.

## Overview

2-3 paragraphs: who this is for, what it covers, why it exists.

## [Content sections — varies by doc]

Each section follows: principle/control → explanation → how we check it.

## Tool Mapping

Table linking standards to automated checks (or "manual review").

## References

External standards, RFCs, further reading.
```

## Per-Document Scope

### 1. `references/security_standards.md`

**Audience:** Developers and code reviewers

Sections:
- **OWASP Top 10 (2021)** — A01 through A10. Each gets 2-3 paragraphs explaining the vulnerability, why it matters, and an example. The tool mapping shows which are caught by `security_scanner.py` vs which require manual review.
- **Secure Coding Practices** — Input validation, output encoding, authentication, session management, error handling, secrets management. Each practice gets a "good vs bad" code example.
- **API Security Controls** — Rate limiting, auth, input validation, CORS configuration.

### 2. `references/vulnerability_management_guide.md`

**Audience:** Security engineers and incident responders

Sections:
- **CVE Triage Process** — Step-by-step with SLA table: Critical (CVSS 9.0+) → 24 hours, High (7.0-8.9) → 7 days, Medium (4.0-6.9) → 30 days, Low (<4.0) → 90 days.
- **CVSS Scoring** — Brief explanation of base / temporal / environmental scores.
- **Remediation Workflow** — Assess → Prioritize → Remediate → Verify cycle, with exit criteria at each stage.
- **Incident Response** — 5-phase process: Detect & Identify → Contain → Eradicate → Recover → Post-Incident. Each phase has duration targets and exit criteria.

### 3. `references/compliance_requirements.md`

**Audience:** Compliance officers and auditors

Sections (one per framework):
- **SOC 2** — CC6 (Logical Access), CC7 (System Operations), CC8 (Change Management)
- **PCI-DSS v4.0** — Req 3/4 (Encryption), Req 6 (Secure Development), Req 8 (Authentication), Req 10/11 (Logging & Testing)
- **HIPAA Security Rule** — 164.312(a)(1) unique user IDs, 164.312(b) audit controls, 164.312(d) person/entity authentication, 164.312(e)(1) transmission security
- **GDPR** — Art 25 (Privacy by Design), Art 32 (Security of Processing), Art 33 (Breach Notification), Art 17 (Right to Erasure), Art 20 (Data Portability)

Each control section includes:
- Control ID and name
- What it requires (2-3 sentences)
- Which automated checks verify it (with tool name and flags)
- Cross-framework overlap notes (e.g., "SOC 2 CC6.1 overlaps with HIPAA 164.312(a)(1)")

**Tool Mapping Table** at the end:

| Framework | Control | Requirement | Checked By | Status |
|-----------|---------|-------------|-----------|--------|
| SOC 2 | CC6.1 | Logical access controls | `compliance_checker.py --framework soc2` | Automated |
| PCI-DSS | Req 6.5 | Secure coding | `security_scanner.py` | Automated |
| HIPAA | 164.312(e)(1) | Transmission encryption | `compliance_checker.py` (TLS scan) | Automated |
| GDPR | Art 33 | Breach notification | — | Manual review |

### 4. `references/secure-coding-checklist.md`

**Audience:** Developers doing PR review and security self-assessment

Flat checklist organized by category. Every item has a unique **check ID** for future automation reference:

- **Input Validation:** SC-IN-001 through SC-IN-005
- **Output Encoding:** SC-OE-001 through SC-OE-004
- **Authentication:** SC-AU-001 through SC-AU-005
- **Session Management:** SC-SM-001 through SC-SM-004
- **Error Handling:** SC-EH-001 through SC-EH-003
- **Secrets Management:** SC-SE-001 through SC-SE-004

Format per item:
```
[ ] SC-IN-001: Validate all input on server side — _automation: planned_
```

Items with `_automation: planned_` are candidates for future automated checks. Items the tool already catches will say `_automation: security_scanner.py_`.

## Error Handling / Maintenance

- Control mappings are **not** code-generated — they're manually maintained alongside the compliance checker
- When a new module or check is added to the tool, the corresponding control mapping in `compliance_requirements.md` should be updated
- The checklist IDs are stable — once assigned, an ID is never reused (deprecated IDs are marked `[DEPRECATED]` inline)

## That's the Design

4 documents, ~2-4 pages each, following a consistent format. The key innovation is the **Tool Mapping** section that explicitly bridges standards to automated checks — making it obvious what's covered and what isn't, both for engineers and auditors.
