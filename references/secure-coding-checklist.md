# Secure Coding Checklist

> Quick-reference checklist for PR review and security self-assessment. Each item has a stable check ID for tracking.

## Overview

Check off items during code review or before merging. Items with `automation: security_scanner.py` are caught by the SAST scanner. Items with `automation: planned` are candidates for future automation. Items with `automation: —` require manual review.

**Audience:** Developers performing code review and security self-assessment.

---

## Input Validation

- [ ] **SC-IN-001:** Validate all input on server side — _automation: security_scanner.py (partial)_
- [ ] **SC-IN-002:** Use allowlists over denylists for input filtering — _automation: —_
- [ ] **SC-IN-003:** Sanitize for specific context (HTML, SQL, shell) — _automation: security_scanner.py (partial)_
- [ ] **SC-IN-004:** Limit input length at the application level — _automation: —_
- [ ] **SC-IN-005:** Reject unexpected Content-Type headers — _automation: —_

## Output Encoding

- [ ] **SC-OE-001:** HTML-encode output rendered in browser — _automation: —_
- [ ] **SC-OE-002:** URL-encode for URLs and query parameters — _automation: —_
- [ ] **SC-OE-003:** JavaScript-encode for script contexts — _automation: —_
- [ ] **SC-OE-004:** Never render unescaped user input in templates — _automation: security_scanner.py_

## Authentication

- [ ] **SC-AU-001:** Use bcrypt (cost 12+) or Argon2id for password hashing — _automation: security_scanner.py (weak crypto detection)_
- [ ] **SC-AU-002:** Implement MFA for sensitive operations — _automation: —_
- [ ] **SC-AU-003:** Enforce strong password policy (min length, complexity) — _automation: —_
- [ ] **SC-AU-004:** Implement account lockout after failed attempts — _automation: —_
- [ ] **SC-AU-005:** Regenerate session ID after login — _automation: —_

## Session Management

- [ ] **SC-SM-001:** Set HttpOnly, Secure, SameSite flags on cookies — _automation: cookies module_
- [ ] **SC-SM-002:** Implement session timeout (15 minutes idle recommended) — _automation: —_
- [ ] **SC-SM-003:** Invalidate session on logout — _automation: —_
- [ ] **SC-SM-004:** Generate cryptographically random session IDs — _automation: —_

## Error Handling

- [ ] **SC-EH-001:** Return generic error messages to end users — _automation: disclosure module (stack trace check)_
- [ ] **SC-EH-002:** Log errors with context (no secrets, no PII) — _automation: —_
- [ ] **SC-EH-003:** Never expose stack traces in production — _automation: disclosure module_

## Secrets Management

- [ ] **SC-SE-001:** Use environment variables or secrets manager — _automation: security_scanner.py (hardcoded secrets)_
- [ ] **SC-SE-002:** Never commit secrets to version control — _automation: security_scanner.py_
- [ ] **SC-SE-003:** Rotate credentials at least every 90 days — _automation: —_
- [ ] **SC-SE-004:** Use short-lived tokens where possible — _automation: —_

---

## Tool Mapping

| Category | Automated Check | Status |
|----------|-----------------|--------|
| Input validation | `security_scanner.py` | Partial |
| Output encoding | `security_scanner.py` | Partial |
| Authentication | `security_scanner.py` (weak crypto), `auth` module | Partial |
| Session management | `cookies` module | Partial |
| Error handling | `disclosure` module | Partial |
| Secrets management | `security_scanner.py` | Automated |

---

## References

- [OWASP Secure Coding Practices Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [SEI CERT Coding Standards](https://wiki.sei.cmu.edu/confluence/display/seccode/SEI+CERT+Coding+Standards)
