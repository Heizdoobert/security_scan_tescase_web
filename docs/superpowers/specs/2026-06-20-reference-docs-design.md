# Design: Security Reference Documentation

**Date:** 2026-06-20
**Status:** Draft

## Problem Statement

The WebSec Test project has a comprehensive SAST scanner, dependency assessor, and compliance checker — but no formal reference documentation that explains *what* each check tests, *why* it matters, or *how* it maps to security standards and compliance frameworks. Engineers running the tool need to understand findings. Auditors need to verify control coverage. Both currently have to reverse-engineer the code.

## Approach

Create **7 lightweight reference documents** in `references/` that serve as the **source of truth** for what the tool checks and why. Each doc follows a consistent format and includes a **Tool Mapping** section that explicitly links each control or standard to the automated check (or marks it as "manual review").

This phase covers **documentation only** — no scripts or tools. Companion scripts like `scripts/threat_modeler.py` and `scripts/secret_scanner.py` referenced by the Senior Security Engineer skill will be implemented in a separate phase.

## Document Structure

All 7 documents share this layout:

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

### 5. `references/threat-modeling-guide.md`

**Audience:** Security architects and engineers performing threat modeling

Sections:
- **STRIDE Methodology** — Explanation of each category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) with per-DFD-element applicability matrix (External Entities → Spoofing + Repudiation, Processes → all 6, Data Stores → Tampering + Repudiation + Info Disclosure + DoS, Data Flows → Tampering + Info Disclosure + DoS).
- **DREAD Scoring** — Damage, Reproducibility, Exploitability, Affected Users, Discoverability — each rated 1-10, averaged for final risk score. Threshold guidance (≥7 needs named mitigation owner).
- **Attack Trees** — How to decompose a threat into atomic attacker steps. Example: "SQL injection via login form" → enumerate endpoints → detect reflection → craft payload → exfiltrate data.
- **DFD Creation** — How to draw data flow diagrams: external entities, processes, data stores, data flows, trust boundaries. Naming conventions and scope boundaries.

**Tool Mapping:**
| Technique | Checked By | Status |
|-----------|-----------|--------|
| STRIDE per DFD element | `scripts/threat_modeler.py` | Docs only (script in future phase) |
| DREAD scoring | `scripts/threat_modeler.py` | Docs only |
| Secret sweep | `scripts/secret_scanner.py` | Docs only |

### 6. `references/security-architecture-patterns.md`

**Audience:** Architects and tech leads designing secure systems

**Boundary with `security_standards.md`:** This doc covers **architecture-level** patterns (system design, network topology, trust boundaries). `security_standards.md` covers **code-level** practices (OWASP, secure coding). They overlap at API security — `security_standards.md` covers OWASP API Top 10 (endpoint hardening), this doc covers API gateway patterns and auth architecture (design decisions).

Sections:
- **Zero Trust Architecture** — Never trust, always verify. Micro-segmentation, least privilege per-request auth, continuous verification vs perimeter-based. Applicability: greenfield vs brownfield, cloud-native vs hybrid.
- **Defense in Depth** — Layered controls: network → host → application → data. Each layer has different attacker cost. Example: WAF → rate limiter → auth → input validation → parameterized queries.
- **Authentication Architecture** — Patterns: session-based, token-based (JWT), OAuth 2.0 / OIDC flows (authorization code, PKCE, client credentials), API keys. When to use each.
- **API Security Architecture** — Gateway patterns (rate limiting, auth aggregation, schema validation), mTLS for service-to-service, webhook signing, idempotency keys.
- **Secret Management Architecture** — Vault vs cloud secret managers vs env vars. Rotation strategies. Emergency access procedures.
- **Secret Scanning Tools** — Comparison of gitleaks, detect-secrets, truffleHog. When to use each: detect-secrets as pre-commit hook (catches before history entry), gitleaks in CI (catches slip-through). Setup guidance for both.
- **Supply Chain Security** — SBOM generation (syft, CycloneDX format), artifact signing (Sigstore/cosign keyless OIDC), SLSA levels 1-4 with what each proves.

### 7. `references/cryptography-implementation.md`

**Audience:** Engineers implementing cryptographic operations

Sections:
- **Symmetric Encryption** — AES-GCM (recommended). Key size requirements (256-bit preferred), nonce/IV generation rules (never reuse with same key), authentication tag verification.
- **Asymmetric Signatures** — Ed25519 (recommended over ECDSA). Why: deterministic, constant-time, smaller signatures. RSA deprecation guidance.
- **Password Hashing** — Argon2id (recommended), bcrypt (acceptable for legacy). Cost parameters (Argon2id: 64MB memory, 3 iterations, 1 parallelism; bcrypt: cost 12+).
- **Key Management** — HSM vs software vaults, key derivation (HKDF), key rotation schedules, emergency key destruction procedures.
- **What Not to Use** — MD5/SHA-1 for signatures, ECB mode, RC4, custom crypto, non-constant-time comparison.

**Tool Mapping:**
| Practice | Checked By | Status |
|----------|-----------|--------|
| Weak crypto detection | `security_scanner.py` (SAST patterns) | Automated |
| TLS version enforcement | SSL/TLS module | Automated |
| Password hashing algorithm | Manual code review | Manual |

## Cross-Document References

Related content between docs should link explicitly:

| From | To | Why |
|------|----|-----|
| `threat-modeling-guide.md` | `compliance_requirements.md` | Threat model findings map to compliance controls |
| `security-architecture-patterns.md` | `security_standards.md` | Architecture patterns reference code-level practices |
| `secure-coding-checklist.md` | `cryptography-implementation.md` | Checklist items SC-CR-001+ reference crypto standards |
| `compliance_requirements.md` | `vulnerability_management_guide.md` | Compliance requires CVE management process |

## Error Handling / Maintenance

- Control mappings are **not** code-generated — they're manually maintained alongside the compliance checker
- When a new module or check is added to the tool, the corresponding control mapping in `compliance_requirements.md` should be updated
- The checklist IDs are stable — once assigned, an ID is never reused (deprecated IDs are marked `[DEPRECATED]` inline)

## Summary

| # | Document | Audience | Pages |
|---|----------|----------|-------|
| 1 | `references/security_standards.md` | Developers, code reviewers | 4-6 |
| 2 | `references/vulnerability_management_guide.md` | Security engineers, incident responders | 3-5 |
| 3 | `references/compliance_requirements.md` | Compliance officers, auditors | 4-6 |
| 4 | `references/secure-coding-checklist.md` | Developers (PR review) | 2-3 |
| 5 | `references/threat-modeling-guide.md` | Security architects | 4-6 |
| 6 | `references/security-architecture-patterns.md` | Architects, tech leads | 5-7 |
| 7 | `references/cryptography-implementation.md` | Engineers implementing crypto | 3-5 |

7 documents, consistent format. All share the **Tool Mapping** section that bridges standards to automated checks — making it obvious what's covered and what isn't, both for engineers and auditors.

**Out of scope (future phases):** `scripts/threat_modeler.py`, `scripts/secret_scanner.py`, and the CI pipeline upgrade. This phase is documentation only.
