# Security Architecture Patterns

> Architecture-level security patterns: Zero Trust, defense in depth, authentication architecture, API security, secret management, secret scanning tools, and supply chain security.

## Overview

This document covers **architecture-level** security decisions — system design, network topology, identity models, and operational security. It complements `references/security_standards.md` (which covers code-level practices) by focusing on design choices that determine the overall security posture of a system.

**Boundary:** `security_standards.md` covers OWASP Top 10 and code-level practices. This doc covers system architecture patterns (network topology, identity architecture, gateway design). API security appears in both: `security_standards.md` covers endpoint hardening (input validation, CORS), this doc covers API gateway patterns and auth architecture (design decisions).

**Audience:** Architects and tech leads designing secure systems.

---

## Zero Trust Architecture

Zero Trust replaces perimeter-based security with a "never trust, always verify" model. Every request is authenticated and authorized regardless of its origin.

### Core Principles

- **Micro-segmentation:** Divide the network into small, isolated zones. Compromise in one zone does not automatically grant access to others.
- **Least privilege per-request auth:** Every API call must be authenticated and authorized. No implicit trust based on network location.
- **Continuous verification:** Re-verify identity and device posture throughout a session, not just at login.

### Applicability

| Scenario | Approach |
|----------|----------|
| Greenfield cloud-native | Full Zero Trust: service mesh (Istio/Linkerd), mTLS everywhere, per-request auth |
| Brownfield migration | Start with external-facing services, add API gateways, incrementally internal services |
| Hybrid (on-prem + cloud) | Identity federation (SSO), VPN-less access with device posture checks |

### Implementation Checklist

- [ ] All services authenticated via identity-aware proxy
- [ ] Network segmentation enforced (no flat network)
- [ ] Service-to-service communication uses mTLS
- [ ] Device posture verified before granting access
- [ ] Session tokens short-lived with refresh rotation

---

## Defense in Depth

Layered security controls ensure that if one layer is breached, the next layer still provides protection.

### Control Layers

```
Network ───── WAF, firewall, network ACLs, DDoS protection
    │
Host ───────── OS hardening, vulnerability scanning, host IDS
    │
Application ── Auth, input validation, output encoding, rate limiting
    │
Data ───────── Encryption at rest, access controls, audit logging
```

### Example: Securing an API Endpoint

```
WAF (SQLi/XSS patterns) → Rate limiter (100 req/min) → Auth (JWT validation)
    → Input validation (schema, length, type) → Parameterized queries (SQL)
```

Each layer increases the attacker's cost. To exploit a SQL injection, an attacker must:

1. Bypass the WAF (layer 1)
2. Evade rate limiting (layer 2)
3. Forge valid authentication (layer 3)
4. Find an input validation gap (layer 4)
5. Still get blocked by parameterized queries (layer 5)

---

## Authentication Architecture

### Session-Based Authentication

- Server stores session state; client stores session cookie
- Simple, well-understood. Best for server-rendered web apps.
- Requires sticky sessions or shared session store (Redis) in multi-instance deployments.

### Token-Based Authentication (JWT)

- Client stores a self-contained JWT. Server validates signature, no session store needed.
- Stateless — good for REST APIs and microservices.
- **Critical:** Keep JWT short-lived (15–60 minutes). Use refresh tokens for long-lived sessions.

### OAuth 2.0 / OIDC Flows

| Flow | Use Case | Security Level |
|------|----------|----------------|
| Authorization Code | Web apps with backend | High (PKCE recommended) |
| Authorization Code + PKCE | Single-page apps, mobile | High (required for SPAs) |
| Client Credentials | Server-to-server M2M | Medium (no user context) |

### API Keys

- Simple, long-lived tokens. Suitable for service accounts and developer access.
- **Risk:** API keys are often hardcoded or exposed in client-side code.
- **Mitigation:** Scan for keys with `security_scanner.py`. Rotate every 90 days.

### Key Comparison

| Method | Stateful | Use Case | Risk |
|--------|----------|----------|------|
| Session | Server-side | Web apps | Session hijacking |
| JWT | Stateless | REST APIs, microservices | Token theft (mitigate with short expiry) |
| OAuth 2.0 | Depends | Third-party auth, delegated access | Phishing of auth codes |
| API Key | Stateless | Service accounts, developer access | Hardcoded secrets |

---

## API Security Architecture

### Gateway Patterns

| Pattern | Description | Tools |
|---------|-------------|-------|
| Rate limiting | Throttle per API key/IP. Burst + sustained limits. | Kong, AWS API Gateway, Envoy |
| Auth aggregation | Validate tokens at gateway before reaching services | Any API gateway |
| Schema validation | Reject malformed payloads at gateway | OpenAPI spec validation |
| IP allow/block lists | Restrict access to known IP ranges | WAF, gateway IP policies |

### Service-to-Service mTLS

- Mutual TLS ensures both sides of a connection present valid certificates
- Prevents man-in-the-middle and unauthorized services from joining the mesh
- **Implementation:** Service mesh (Istio, Linkerd) automates mTLS. Manual mTLS requires certificate rotation infrastructure.

### Webhook Signing

- Sign webhook payloads with HMAC-SHA256 using a shared secret
- Receiver verifies signature before processing
- Prevents replay attacks and payload tampering

```python
# Sender
signature = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()

# Receiver: verify before processing
expected = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
if not hmac.compare_digest(signature, expected):
    raise SecurityError("Invalid webhook signature")
```

### Idempotency Keys

- Client sends `Idempotency-Key: <UUID>` header on mutating requests
- Server stores processed keys; returns cached response on duplicate
- **Use case:** Payment processing, order creation — any operation that must execute exactly once

---

## Secret Management Architecture

### Storage Options

| Option | Best For | Rotation | Audit |
|--------|----------|----------|-------|
| HashiCorp Vault | Enterprise, multi-cloud | Automated | Full |
| Cloud secret manager (AWS/GCP/Azure) | Cloud-native apps | Automated | Full |
| Encrypted env vars | Small teams, containers | Manual | Limited |
| .env files (gitignored) | Local dev only | Manual | None |

### Rotation Strategies

- **Scheduled rotation:** Rotate every 90 days for all secrets (enforce via policy in Vault)
- **Emergency rotation:** Immediate rotation on compromise (require break-glass procedure)
- **Zero-downtime rotation:** Dual-key scheme — accept old and new key during rotation window, deactivate old after verification

### Emergency Access

- Define break-glass procedure for accessing secrets when normal auth is unavailable
- Document: who can approve, how it's logged, how access is revoked after emergency
- Review break-glass usage monthly

---

## Secret Scanning Tools

Choose the right scanner for each stage of your workflow:

| Tool | Best For | Language | Pre-commit | CI/CD | Custom Rules |
|------|----------|----------|:----------:|:-----:|:------------:|
| **gitleaks** | CI pipelines, full-repo scans | Go | Yes | Yes | TOML regex |
| **detect-secrets** | Pre-commit hooks, incremental | Python | Yes | Partial | Plugin-based |
| **truffleHog** | Deep history scans, entropy | Go | No | Yes | Regex + entropy |

### Recommended Setup

- **Pre-commit:** `detect-secrets` catches secrets before they enter version control
- **CI/CD:** `gitleaks` catches anything that slips through pre-commit

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/Yelp/detect-secrets
  rev: v1.4.0
  hooks:
    - id: detect-secrets
      args: ['--baseline', '.secrets.baseline']
```

```yaml
# .github/workflows/secret-scan.yml
- name: gitleaks
  uses: gitleaks/gitleaks-action@v2
```

**Note:** The project's `security_scanner.py` also detects hardcoded secrets in source code on every scan, providing an additional layer of defense.

---

## Supply Chain Security

Protect against dependency and artifact tampering with SBOM generation, artifact signing, and SLSA compliance.

### SBOM Generation

| Tool | Format | How |
|------|--------|-----|
| **syft** | SPDX, CycloneDX | Scan container images or source directories |
| **cyclonedx-cli** | CycloneDX | Native tooling; merge multiple SBOMs for monorepos |

```bash
# Generate SBOM from container image
syft packages ghcr.io/org/app:latest -o cyclonedx-json > sbom.json
```

### Artifact Signing

- **Sigstore/cosign** enables keyless signing via OIDC identity

```bash
# Sign a container image
cosign sign ghcr.io/org/app:latest

# Verify signature
cosign verify ghcr.io/org/app:latest \
    --certificate-identity=ci@org.com \
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

### SLSA Levels

| Level | Requirement | What It Proves |
|-------|-------------|----------------|
| 1 | Build process documented | Provenance exists |
| 2 | Hosted build service, signed provenance | Tamper-resistant provenance |
| 3 | Hardened build platform, non-falsifiable provenance | Tamper-proof build |
| 4 | Two-party review, hermetic builds | Maximum supply-chain assurance |

---

## Tool Mapping

| Architecture Pattern | Checked By | Status |
|---------------------|-----------|--------|
| Zero Trust — mTLS enforcement | `ssl_tls` module | Automated |
| Defense in depth — multiple layers | — | Manual (design review) |
| Auth architecture — session/token security | `auth`, `cookies` modules | Automated |
| API gateway — rate limiting | — | Manual |
| API security — CORS | `cors` module | Automated |
| Secret management — hardcoded secrets | `security_scanner.py` | Automated |
| Secret scanning external tools | gitleaks/detect-secrets/truffleHog | External (configurable in CI) |
| Supply chain — SBOM | `vulnerability_assessor.py` | Partial (CVE matching) |
| Supply chain — artifact signing | — | Manual |

---

## References

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [IETF RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore / cosign Documentation](https://docs.sigstore.dev/)
- [OAuth 2.0 Authorization Framework (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
