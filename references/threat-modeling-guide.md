# Threat Modeling Guide

> STRIDE methodology, DREAD risk scoring, attack trees, and data flow diagrams for structured security analysis.

## Overview

Threat modeling is a structured approach to identifying and mitigating security threats during design. This guide covers the STRIDE methodology for classifying threats, DREAD for prioritizing them, attack trees for decomposing complex attacks, and data flow diagrams for visualizing system architecture. Use this alongside automated scanning tools to ensure both known and unknown threats are addressed.

**Audience:** Security architects and engineers performing threat modeling during design reviews.

---

## STRIDE Methodology

STRIDE classifies threats into six categories. Each Data Flow Diagram (DFD) element is susceptible to specific STRIDE categories.

### Per-DFD Element Applicability

| DFD Element | S | T | R | I | D | E | Notes |
|-------------|---|---|---|---|---|---|-------|
| External Entity | ✓ | — | ✓ | — | — | — | Spoofing (identity), Repudiation (no audit trail) |
| Process | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | All STRIDE categories apply |
| Data Store | — | ✓ | ✓ | ✓ | ✓ | — | Tampering, Repudiation, Info Disclosure, DoS |
| Data Flow | — | ✓ | — | ✓ | ✓ | — | Tampering, Info Disclosure, DoS |

### STRIDE Categories

**Spoofing** — Attacker impersonates a user, system, or component.
- _Example:_ Stealing session tokens or forging authentication headers.
- _Mitigation:_ Strong authentication, MFA, certificate-based identity.

**Tampering** — Unauthorized modification of data or code.
- _Example:_ Modifying a request payload in transit to bypass authorization.
- _Mitigation:_ Integrity checks (HMAC, digital signatures), input validation.

**Repudiation** — User denies performing an action without the ability to prove otherwise.
- _Example:_ A user claims they didn't initiate a funds transfer.
- _Mitigation:_ Audit logging with timestamp and user identity, digital signatures.

**Information Disclosure** — Exposure of data to unauthorized parties.
- _Example:_ Stack traces revealing internal paths; database error messages leaking schema.
- _Mitigation:_ Encryption (TLS, AES), access controls, generic error messages.

**Denial of Service** — System becomes unavailable to legitimate users.
- _Example:_ Flooding an endpoint with expensive database queries.
- _Mitigation:_ Rate limiting, resource quotas, auto-scaling.

**Elevation of Privilege** — Unprivileged user gains higher-level access.
- _Example:_ Regular user role escalation to admin via parameter tampering.
- _Mitigation:_ Strict role checks on every endpoint, horizontal/vertical access control testing.

---

## DREAD Scoring

DREAD provides a numerical risk score for each identified threat. Each category is rated 1–10.

| Category | Description | Rating Guide |
|----------|-------------|--------------|
| **D**amage | How severe is the damage? | 1=minor info leak, 10=complete system compromise |
| **R**eproducibility | How easy is it to reproduce? | 1=very hard, 10=trivially repeatable |
| **E**xploitability | How easy is it to exploit? | 1=requires physical access, 10=unauthenticated remote |
| **A**ffected Users | How many users are affected? | 1=one user, 10=all users |
| **D**iscoverability | How easy is it to discover? | 1=very hard, 10=publicly known |

**Score:** Average the five categories. Round to one decimal place.

| Score Range | Severity | Action Required |
|------------|----------|----------------|
| 7.0 – 10.0 | Critical | Named mitigation owner required. Must be addressed before release. |
| 4.0 – 6.9 | High | Mitigation plan required. Track in backlog with SLA. |
| 1.0 – 3.9 | Medium | Accept risk or add compensating control. |

---

## Attack Trees

Attack trees decompose a high-level threat into atomic attacker steps. Each node is a step the attacker must complete.

### Example: SQL Injection via Login Form

```
SQL Injection via Login Form
├── 1.0 Find login form
│   └── 1.1 Crawl site for form tags with password fields
├── 2.0 Detect SQL injection reflection
│   ├── 2.1 Submit single quote (') in username field
│   ├── 2.2 Submit time-based payload (SLEEP(5)) in password field
│   └── 2.3 Detect error message or time delay in response
├── 3.0 Craft injection payload
│   ├── 3.1 Bypass authentication: ' OR '1'='1' --
│   ├── 3.2 Extract column count via ORDER BY
│   └── 3.3 Extract database info via UNION SELECT
└── 4.0 Exfiltrate data
    └── 4.1 Use UNION SELECT to retrieve user credentials
```

**Tool mapping:** Steps 1.0–2.0 are partially automated by the `injection` module. Steps 3.0–4.0 require manual penetration testing.

---

## DFD Creation

Data Flow Diagrams model system architecture for threat analysis.

### DFD Elements

| Shape | Element | Description |
|-------|---------|-------------|
| Rectangle | External Entity | User, external system, service (outside your control) |
| Circle/Elipse | Process | Application component, service, function |
| Parallel lines | Data Store | Database, file system, cache |
| Arrow | Data Flow | Direction of data movement |
| Dotted line | Trust Boundary | Boundary between trust levels (e.g., DMZ to internal network) |

### Naming Conventions

- **External Entities:** `[Role]` (e.g., `End User`, `Payment Gateway`)
- **Processes:** `[Verb] [Noun]` (e.g., `Authenticate User`, `Process Payment`)
- **Data Stores:** `[Noun] Store` (e.g., `User Store`, `Session Store`)
- **Data Flows:** `[Data] [Direction]` (e.g., `Credentials →`, `← User Profile`)

### Scope Boundaries

- Include only components within the system under review
- Draw trust boundaries at network segments, DMZs, cloud VPC boundaries
- Label data flows with the protocol and encryption status (e.g., "HTTPS (TLS 1.3)")
- Keep DFD to one logical system per diagram — split complex systems into level 0, level 1, etc.

---

## Tool Mapping

| Technique | Checked By | Status |
|-----------|-----------|--------|
| STRIDE per DFD element | `scripts/threat_modeler.py` | Docs only (script in future phase) |
| DREAD scoring | `scripts/threat_modeler.py` | Docs only |
| Attack tree decomposition | `injection` module (partial) | Manual + partial automation |
| DFD creation | — | Manual |
| Secret sweep | `scripts/secret_scanner.py` | Docs only (script in future phase) |

---

## References

- [Microsoft STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [NIST SP 800-154: Guide to Data-Centric System Threat Modeling](https://csrc.nist.gov/publications/detail/sp/800-154/draft)
- [PASTA Threat Modeling Methodology](https://www.veracode.com/security/pasta-threat-modeling)
