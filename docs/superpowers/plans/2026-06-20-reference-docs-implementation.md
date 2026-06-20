# Implementation Plan: Security Reference Documentation

**Date:** 2026-06-20
**Design:** `docs/superpowers/specs/2026-06-20-reference-docs-design.md`
**Status:** Ready for execution

---

## Objective

Create 7 security reference documents in `references/` that serve as the source of truth for what the WebSec Test tool checks and why. Each doc follows a consistent format with a Tool Mapping section linking standards to automated checks.

This phase is **documentation only** — no scripts or tools.

---

## Pre-Flight Checks

1. Verify `references/` directory exists at project root (create if missing)
2. Verify the design doc at `docs/superpowers/specs/2026-06-20-reference-docs-design.md` is readable
3. Verify the following tool names match actual project files:
   - `scripts/security_scanner.py`
   - `scripts/vulnerability_assessor.py`
   - `scripts/compliance_checker.py`
   - `websec_test/modules/` — all 10 modules exist (headers, auth, csrf, injection, authz, ssl_tls, cors, cookies, disclosure, methods)
4. Confirm no existing files at `references/*.md` that would be overwritten

---

## Task List

All 7 tasks can run in **parallel** — no cross-file dependencies.

### Task 1: `references/security_standards.md`

**Audience:** Developers and code reviewers | **Pages:** 4-6

Content:
- **OWASP Top 10 (2021)** — A01 through A10. Each: 2-3 paragraphs explaining vulnerability, why it matters, example. Tool mapping shows which `security_scanner.py` catches vs manual review.
- **Secure Coding Practices** — Input validation, output encoding, authentication, session management, error handling, secrets management. Each with good vs bad code examples (Python/JS).
- **API Security Controls** — Rate limiting, auth, input validation, CORS configuration.

### Task 2: `references/vulnerability_management_guide.md`

**Audience:** Security engineers and incident responders | **Pages:** 3-5

Content:
- **CVE Triage Process** — Step-by-step with SLA table: Critical (CVSS 9.0+) → 24h, High (7.0-8.9) → 7d, Medium (4.0-6.9) → 30d, Low (<4.0) → 90d.
- **CVSS Scoring** — Base / temporal / environmental scores explanation.
- **Remediation Workflow** — Assess → Prioritize → Remediate → Verify cycle with exit criteria.
- **Incident Response** — 5-phase: Detect & Identify (0-15min), Contain (15-60min), Eradicate (1-4h), Recover (4-24h), Post-Incident (24-72h). Each phase has duration targets and exit criteria.

### Task 3: `references/compliance_requirements.md`

**Audience:** Compliance officers and auditors | **Pages:** 4-6

Content per framework:
- **SOC 2** — CC6 (Logical Access), CC7 (System Operations), CC8 (Change Management)
- **PCI-DSS v4.0** — Req 3/4 (Encryption), Req 6 (Secure Dev), Req 8 (Auth), Req 10/11 (Logging & Testing)
- **HIPAA Security Rule** — 164.312(a)(1) unique user IDs, 164.312(b) audit controls, 164.312(d) auth, 164.312(e)(1) transmission security
- **GDPR** — Art 25 (Privacy by Design), Art 32 (Security), Art 33 (Breach Notification), Art 17 (Erasure), Art 20 (Portability)

Each control: ID + name, requirement (2-3 sentences), which automated check verifies it (tool name + flags), cross-framework overlap notes.

**Tool Mapping Table** at end:
| Framework | Control | Requirement | Checked By | Status |
| SOC 2 | CC6.1 | Logical access | compliance_checker.py --framework soc2 | Automated |
| PCI-DSS | Req 6.5 | Secure coding | security_scanner.py | Automated |
| HIPAA | 164.312(e)(1) | TLS encryption | compliance_checker.py (TLS scan) | Automated |
| GDPR | Art 33 | Breach notification | — | Manual review |

### Task 4: `references/secure-coding-checklist.md`

**Audience:** Developers doing PR review | **Pages:** 2-3

Flat checklist with unique check IDs:
- **Input Validation:** SC-IN-001 through SC-IN-005
- **Output Encoding:** SC-OE-001 through SC-OE-004
- **Authentication:** SC-AU-001 through SC-AU-005
- **Session Management:** SC-SM-001 through SC-SM-004
- **Error Handling:** SC-EH-001 through SC-EH-003
- **Secrets Management:** SC-SE-001 through SC-SE-004

Format per item:
```
[ ] SC-IN-001: Validate all input on server side — automation: planned
```

Items with `automation: planned` are candidates for future automated checks. Items already caught by the tool say `automation: security_scanner.py`.

### Task 5: `references/threat-modeling-guide.md`

**Audience:** Security architects | **Pages:** 4-6

Content:
- **STRIDE Methodology** — Per-DFD-element applicability matrix (External Entities→Spoofing+Repudiation, Processes→all 6, Data Stores→Tampering+Repudiation+Info Disclosure+DoS, Data Flows→Tampering+Info Disclosure+DoS).
- **DREAD Scoring** — Damage, Reproducibility, Exploitability, Affected Users, Discoverability. Each 1-10, averaged. Threshold: ≥7 needs named mitigation owner.
- **Attack Trees** — Decompose threat into atomic steps. Example: SQL injection via login form.
- **DFD Creation** — External entities, processes, data stores, data flows, trust boundaries. Naming conventions.

Tool Mapping:
| Technique | Checked By | Status |
| STRIDE per DFD element | threat_modeler.py | Docs only (future phase) |
| DREAD scoring | threat_modeler.py | Docs only |
| Secret sweep | secret_scanner.py | Docs only |

### Task 6: `references/security-architecture-patterns.md`

**Audience:** Architects and tech leads | **Pages:** 5-7

Content:
- **Zero Trust Architecture** — Never trust, always verify. Micro-segmentation, least privilege, continuous verification.
- **Defense in Depth** — Layered controls: network→host→application→data. Example: WAF→rate limiter→auth→input validation→parameterized queries.
- **Authentication Architecture** — Session-based, JWT, OAuth 2.0/OIDC flows, API keys. When to use each.
- **API Security Architecture** — Gateway patterns, mTLS, webhook signing, idempotency keys.
- **Secret Management Architecture** — Vault vs cloud managers vs env vars. Rotation strategies.
- **Secret Scanning Tools** — gitleaks vs detect-secrets vs truffleHog comparison. Pre-commit + CI setup guidance.
- **Supply Chain Security** — SBOM generation (syft, CycloneDX), artifact signing (Sigstore/cosign), SLSA levels 1-4.

### Task 7: `references/cryptography-implementation.md`

**Audience:** Engineers implementing crypto | **Pages:** 3-5

Content:
- **Symmetric Encryption** — AES-GCM (recommended). 256-bit key, nonce/IV never reuse with same key, auth tag verification.
- **Asymmetric Signatures** — Ed25519 (recommended over ECDSA). Deterministic, constant-time, smaller signatures. RSA deprecation guidance.
- **Password Hashing** — Argon2id (recommended), bcrypt (acceptable legacy). Parameters: Argon2id 64MB/3 iterations/1 parallelism, bcrypt cost 12+.
- **Key Management** — HSM vs software vaults, HKDF derivation, rotation schedules, emergency destruction.
- **What Not to Use** — MD5/SHA-1 for signatures, ECB mode, RC4, custom crypto, non-constant-time comparison.

Tool Mapping:
| Practice | Checked By | Status |
| Weak crypto detection | security_scanner.py (SAST patterns) | Automated |
| TLS version enforcement | SSL/TLS module | Automated |
| Password hashing algorithm | Manual code review | Manual |

---

## Verification

After all 7 files are created:

1. **File existence:** Verify `references/security_standards.md`, `references/vulnerability_management_guide.md`, `references/compliance_requirements.md`, `references/secure-coding-checklist.md`, `references/threat-modeling-guide.md`, `references/security-architecture-patterns.md`, `references/cryptography-implementation.md` all exist
2. **Format consistency:** Spot-check each doc has: purpose statement, Overview section, content sections, Tool Mapping table, References section
3. **Tool reference check:** Confirm all tool name references (security_scanner.py, vulnerability_assessor.py, compliance_checker.py, module names) match actual project files
4. **Out-of-scope check:** Verify no reference to threat_modeler.py or secret_scanner.py as "automated" — they must say "future phase" or "docs only"
5. **ID stability:** Verify no duplicate SC-XXX IDs in secure-coding-checklist.md

---

## Rollback

If anything goes wrong:

```powershell
Remove-Item -LiteralPath "references" -Recurse -Force
git checkout -- docs/superpowers/specs/2026-06-20-reference-docs-design.md
```

This removes all generated docs and restores the design doc to its last committed state.
