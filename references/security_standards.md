# Security Standards Reference

> Maps OWASP Top 10, secure coding practices, and API security controls to automated checks in the WebSec Test tool.

## Overview

This document covers three layers of security knowledge: the OWASP Top 10 vulnerabilities every developer should know, secure coding practices with concrete good-vs-bad examples, and API-specific security controls. Each section includes a mapping to automated checks — showing which findings the tool catches and which require manual review.

**Audience:** Developers and code reviewers who need to understand security findings and ensure code meets baseline standards.

---

## OWASP Top 10 (2021)

### A01: Broken Access Control

Failure to enforce restrictions on what authenticated users can do. Attackers exploit these flaws to access unauthorized functionality or data.

**Example:** A user changes `?user_id=123` to `?user_id=124` in the URL and sees another user's data.

**How we check it:** The `authz` module tests for forced browsing (open admin/config endpoints) and IDOR (sequential user ID enumeration). `security_scanner.py` catches hardcoded role bypass patterns in source code.

**Tool mapping:** `authz` module — automated; `security_scanner.py` — partial (pattern-dependent)

### A02: Cryptographic Failures

Previously "Sensitive Data Exposure." Weak or missing encryption for data in transit or at rest.

**Example:** TLS disabled on a login page; passwords stored as MD5 hashes.

**How we check it:** The `ssl_tls` module checks certificate expiry, weak protocols (TLS 1.0), and HSTS preload readiness. `security_scanner.py` detects weak crypto algorithms (MD5, SHA-1, ECB, RC4) in source code.

**Tool mapping:** `ssl_tls` module — automated; `security_scanner.py` — automated

### A03: Injection

SQL, NoSQL, OS command, and LDAP injection occur when untrusted data is sent to an interpreter as part of a command or query.

**Example:** `SELECT * FROM users WHERE id = '1' OR '1'='1'` returns all users.

**How we check it:** The `injection` module sends reflective SQLi, XSS, and command injection payloads and checks the response. `security_scanner.py` detects string concatenation in SQL queries, f-string injection, and unsafe shell calls in source code.

**Tool mapping:** `injection` module — automated; `security_scanner.py` — automated

### A04: Insecure Design

Risks related to design and architecture flaws. A secure development lifecycle with threat modeling is the primary defense.

**Example:** No rate limiting on a password reset endpoint allows brute-force token enumeration.

**How we check it:** Design review is inherently manual. See `references/threat-modeling-guide.md` for STRIDE/DREAD methodology.

**Tool mapping:** No automated check — manual design review and threat modeling

### A05: Security Misconfiguration

Missing security hardening, unnecessary features enabled, default accounts unchanged, overly permissive CORS.

**Example:** Directory listing enabled; default admin credentials unchanged.

**How we check it:** The `headers` module checks for missing security headers (HSTS, CSP, X-Frame-Options). The `methods` module tests for TRACE/PUT/DELETE enabled. `disclosure` module checks directory listing and server banners.

**Tool mapping:** `headers` module — automated; `methods` module — automated; `disclosure` module — automated

### A06: Vulnerable and Outdated Components

Using libraries and frameworks with known vulnerabilities.

**Example:** A dependency with a known RCE vulnerability is included without version pinning.

**How we check it:** `vulnerability_assessor.py` scans `requirements.txt`, `pyproject.toml`, `package.json`, and `go.mod` against a curated CVE dictionary.

**Tool mapping:** `vulnerability_assessor.py` — automated

### A07: Identification and Authentication Failures

Weak authentication mechanisms, credential brute-forcing, session fixation, missing MFA.

**Example:** Login form accepts blank passwords; session tokens not invalidated on logout.

**How we check it:** The `auth` module tests for login form discovery, blank-password acceptance, and SQL injection login bypass. The `cookies` module checks for missing Secure, HttpOnly, and SameSite flags.

**Tool mapping:** `auth` module — automated; `cookies` module — automated

### A08: Software and Data Integrity Failures

CI/CD pipeline without integrity checks, unsigned artifacts, insecure update mechanisms.

**Example:** Pipeline downloads unsigned dependencies from untrusted sources.

**How we check it:** Manual review of supply chain security. See `references/security-architecture-patterns.md` for SLSA levels and artifact signing guidance.

**Tool mapping:** No automated check — manual CI/CD and supply chain review

### A09: Security Logging and Monitoring Failures

Insufficient logging, missing alerts, unmonitored authentication failures.

**Example:** Brute-force attack against login goes undetected because failed attempts are not logged.

**How we check it:** `compliance_checker.py` verifies that audit logging controls exist per SOC 2 CC7 and HIPAA 164.312(b).

**Tool mapping:** `compliance_checker.py` — partial (policy verification, not log content analysis)

### A10: Server-Side Request Forgery (SSRF)

Server fetches a user-supplied URL without validation, allowing access to internal systems.

**Example:** Attacker provides `http://169.254.169.254/latest/meta-data/` to fetch cloud provider metadata.

**How we check it:** Manual code review. `security_scanner.py` can catch some URL-from-user-input patterns but cannot verify the full SSRF attack surface without runtime testing.

**Tool mapping:** `security_scanner.py` — partial (pattern-dependent)

---

## Secure Coding Practices

### Input Validation

| Practice | Good | Bad |
|----------|------|-----|
| Validate on server side | `def process(data): if not isinstance(data, int): raise Error(...)` | Relying solely on client-side JavaScript validation |
| Use allowlists | `ALLOWED_CHARS = re.compile(r'^[a-zA-Z0-9_]+$')` | Blocklisting dangerous characters only |
| Context-specific sanitization | Parameterized queries for SQL, HTML escaping for output | One-size-fits-all sanitization |
| Limit input length | `if len(input) > 1000: raise ValidationError(...)` | Accepting arbitrarily long inputs |

### Output Encoding

| Practice | Good | Bad |
|----------|------|-----|
| HTML encode for browser | `html.escape(user_input)` | `template = f"<div>{user_input}</div>"` |
| URL encode | `urllib.parse.quote(url)` | Direct string concatenation for URLs |
| JavaScript encode | JSON serialization before injecting into `<script>` | Template literals with user input |

### Authentication

| Practice | Good | Bad |
|----------|------|-----|
| Strong password hashing | `bcrypt.hashpw(pass, bcrypt.gensalt(12))` | MD5 or SHA-256 for password storage |
| MFA for sensitive ops | Require TOTP or WebAuthn for admin actions | Single factor for all operations |
| Account lockout | Lock after 5 failed attempts with 15min cooldown | Unlimited login attempts |

### Session Management

| Practice | Good | Bad |
|----------|------|-----|
| Secure cookie flags | `Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax` | Cookies without any security flags |
| Session timeout | Idle timeout of 15 minutes | Sessions that last indefinitely |
| Regenerate on auth | `session.regenerate_id()` after login | Keeping the same session ID before and after auth |

### Error Handling

| Practice | Good | Bad |
|----------|------|-----|
| Generic user messages | "An error occurred. Please try again." | Full stack trace exposed to end user |
| Log with context | `logger.error(f"Failed login for user {user_id} from IP {ip}")` | Logging without identifiers or with passwords included |
| No secrets in logs | Log "connection refused" not "password=secret123" | Printing credentials or tokens in error output |

### Secrets Management

| Practice | Good | Bad |
|----------|------|-----|
| Environment variables | `API_KEY = os.environ.get("API_KEY")` | `API_KEY = "sk-1234567890abcdef"` |
| Secrets manager | `get_secret("api/key")` from vault service | Secrets committed to version control |
| Rotation | Automated rotation every 90 days | Never rotated; same key for years |

---

## API Security Controls

| Control | Description | How We Check |
|---------|-------------|--------------|
| Rate limiting | Throttle requests per IP/user to prevent abuse | Manual review — code inspection |
| Authentication | Require valid tokens/session for all protected endpoints | `auth` module — automated |
| Input validation | Validate Content-Type, schema, length, range | Manual review |
| CORS | Restrict origins; never use `Access-Control-Allow-Origin: *` | `cors` module — automated |
| Content-Type enforcement | Reject requests with unexpected Content-Type headers | Manual review |
| Idempotency keys | Prevent duplicate processing on retries | Manual review |

---

## Tool Mapping

| Standard / Practice | Automated Check | Status |
|--------------------|-----------------|--------|
| OWASP A01 — Broken Access Control | `authz` module, `security_scanner.py` | Automated |
| OWASP A02 — Cryptographic Failures | `ssl_tls` module, `security_scanner.py` | Automated |
| OWASP A03 — Injection | `injection` module, `security_scanner.py` | Automated |
| OWASP A04 — Insecure Design | — | Manual (threat modeling) |
| OWASP A05 — Security Misconfiguration | `headers`, `methods`, `disclosure` modules | Automated |
| OWASP A06 — Vulnerable Components | `vulnerability_assessor.py` | Automated |
| OWASP A07 — Auth Failures | `auth`, `cookies` modules | Automated |
| OWASP A08 — Integrity Failures | — | Manual (supply chain review) |
| OWASP A09 — Logging Failures | `compliance_checker.py` | Partial |
| OWASP A10 — SSRF | `security_scanner.py` | Partial |
| Secure Coding — Input Validation | `security_scanner.py` | Partial |
| Secure Coding — Output Encoding | `security_scanner.py` | Partial |
| Secure Coding — Auth / Session | `auth`, `cookies` modules | Automated |
| Secure Coding — Secrets Mgmt | `security_scanner.py` | Automated |
| API Security — CORS | `cors` module | Automated |
| API Security — Rate Limiting | — | Manual |

---

## References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CWE/SANS Top 25 Most Dangerous Software Errors](https://www.sans.org/top25-software-errors/)
