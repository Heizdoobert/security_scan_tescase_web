# OWASP Top 10 (2021) — Penetration Test Checklist

> Test procedures for each OWASP Top 10 category used by the pen-testing skill.

## A01: Broken Access Control

**Test:** Forced browsing, IDOR, privilege escalation.

- Enumerate accessible paths beyond authenticated scope
- Modify URL parameters, request body, or headers to access unauthorized resources
- Test horizontal (same-role different-user) and vertical (low-priv to admin) escalation
- Verify API endpoints enforce per-request authorization, not just UI hiding

**Automation:** `--modules authz`

## A02: Cryptographic Failures

**Test:** Weak TLS, missing HSTS, sensitive data in transit.

- Check TLS version (reject < 1.2), cipher strength, certificate validity
- Verify HSTS header present and preload-ready
- Check cookies for Secure + HttpOnly flags
- Test for sensitive data in URL parameters, referrer headers, or logs

**Automation:** `--modules configuration.ssl_tls configuration.cookies`

## A03: Injection

**Test:** SQLi, NoSQLi, command injection, XSS reflected/stored.

- Submit SQL metacharacters (', ", ;, --) to all input fields
- Test NoSQL operators ($ne, $gt, $regex) in JSON/query parameters
- Inject OS commands into file upload names, header values, and form fields
- Submit `<script>`, `<img onerror>`, and event handler payloads to all user inputs
- Verify parameterized queries and output encoding on every endpoint

**Automation:** `--modules injection.sqli injection.nosql injection.cmd_injection injection.xss`

## A04: Insecure Design

**Test:** Missing rate limiting, weak auth flow, business logic flaws.

- Send rapid sequential requests to detect rate limiting absence
- Test password reset, account recovery, and MFA enrollment flows
- Verify business logic prevents negative quantities, self-approval, etc.
- Check for missing CSRF tokens on state-changing endpoints

**Automation:** `--modules authentication.auth authentication.csrf`

## A05: Security Misconfiguration

**Test:** Default credentials, unnecessary HTTP methods, verbose errors.

- Test for default accounts (admin/admin, root/root)
- Enumerate allowed HTTP methods on each endpoint (TRACE, PUT, DELETE)
- Trigger 500 errors to check for stack traces in responses
- Verify SecurityHeaders.io check: CSP, X-Frame-Options, X-Content-Type-Options

**Automation:** `--modules authentication.auth configuration.headers configuration.methods configuration.disclosure`

## A06: Vulnerable and Outdated Components

**Test:** Known CVEs in dependencies, outdated server software.

- Scan requirements.txt / package.json / Gemfile for known vulnerable versions
- Check Server and X-Powered-By headers for version disclosure
- Verify software versions against CVE database (OS, web server, frameworks)

**Automation:** Use `--secops` (dependency assessment phase)

## A07: Identification and Authentication Failures

**Test:** Weak password policy, credential stuffing, session fixation.

- Test blank or common passwords accepted
- Verify account lockout after N failed attempts
- Test session token regeneration after login
- Check for predictable session tokens or tokens in URL

**Automation:** `--modules authentication.auth`

## A08: Software and Data Integrity Failures

**Test:** Unsigned updates, CI/CD injection, untrusted data sources.

- Verify software updates signed and served over HTTPS
- Check CI/CD pipelines for unsigned artifacts
- Test deserialization of untrusted data (pickle, YAML, XML)

**Automation:** Manual review / `--secops` (compliance phase)

## A09: Security Logging and Monitoring Failures

**Test:** Missing audit logs, insufficient monitoring, unlogged failures.

- Verify all auth failures logged (timestamp, source IP, target resource)
- Check error responses for stack traces that indicate unhandled exceptions
- Confirm security events (password change, privilege escalation) are logged

**Automation:** Manual review / `--secops` (compliance phase)

## A10: Server-Side Request Forgery (SSRF)

**Test:** URL injection, internal network access via parameters.

- Submit internal IP addresses (127.0.0.1, 10.x.x.x, 172.16.x.x, 192.168.x.x) to URL fields
- Test URL scheme variations (file://, gopher://, dict://)
- Verify server-side URL fetch functions validate both host and scheme
- Check for cloud metadata endpoint access (169.254.169.254)

**Automation:** Manual review (no automated check currently)

## References

- OWASP Top 10 (2021): https://owasp.org/www-project-top-ten/
- OWASP Testing Guide v5: https://owasp.org/www-project-web-security-testing-guide/
