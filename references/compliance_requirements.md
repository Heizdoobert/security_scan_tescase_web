# Compliance Requirements

> Maps SOC 2, PCI-DSS, HIPAA, and GDPR control requirements to automated checks in the WebSec Test tool.

## Overview

This document maps compliance control requirements across four major frameworks to the tool's automated checks. Each control shows what it requires, how we verify it, and where frameworks overlap. Use this to audit coverage and identify gaps that need manual review.

**Audience:** Compliance officers and auditors verifying control coverage and generating evidence for certifications.

---

## SOC 2 Type II

### CC6: Logical and Physical Access Controls

| Control | Requirement | How We Check | Status |
|---------|-------------|-------------|--------|
| CC6.1 | Logical access controls for systems | `auth` module (auth bypass testing) | Automated |
| CC6.2 | Registration and de-registration of users | Manual review | Manual |
| CC6.3 | Authentication mechanisms | `auth` module, `cookies` module (session security) | Automated |
| CC6.6 | Authorization controls | `authz` module (forced browsing, IDOR) | Automated |
| CC6.7 | Encryption of data in transit | `ssl_tls` module (TLS version, cert expiry) | Automated |

**Cross-framework overlap:** CC6.1 overlaps with HIPAA 164.312(a)(1). CC6.7 overlaps with PCI-DSS Req 4.

### CC7: System Operations

| Control | Requirement | How We Check | Status |
|---------|-------------|-------------|--------|
| CC7.1 | Monitoring and detection procedures | Manual — alerting pipeline setup | Manual |
| CC7.2 | Incident response process | See `references/vulnerability_management_guide.md` | Manual |
| CC7.4 | System vulnerabilities monitored | `vulnerability_assessor.py` | Automated |

### CC8: Change Management

| Control | Requirement | How We Check | Status |
|---------|-------------|-------------|--------|
| CC8.1 | Changes are authorized and tested | Manual — CI/CD code review policy | Manual |

---

## PCI-DSS v4.0

### Requirement 3: Protect Stored Account Data

| Control | Requirement | How We Check | Status |
|---------|-------------|-------------|--------|
| 3.4 | Render PAN unreadable | `security_scanner.py` (find hardcoded secrets) | Partial |
| 3.5 | Document cryptographic key mgmt | Manual review | Manual |

### Requirement 4: Encrypt Transmission

| Control | Requirement | How We Check | Status |
|---------|-------------|-------------|--------|
| 4.2.1 | TLS 1.2+ for all cardholder data | `ssl_tls` module (TLS version check) | Automated |
| 4.2.1.1 | Strong crypto for transmissions | `ssl_tls` module (cipher suite detection) | Automated |

### Requirement 6: Develop and Maintain Secure Systems

| Control | Requirement | How We Check | Status |
|---------|-------------|-------------|--------|
| 6.2.1 | Update software promptly | `vulnerability_assessor.py` (CVE scan) | Automated |
| 6.3.2 | SAST for custom code | `security_scanner.py` | Automated |
| 6.4.1 | Change management process | Manual review | Manual |
| 6.4.2 | Separate dev/test/prod environments | Manual review | Manual |

**Cross-framework overlap:** Req 6.3.2 overlaps with SOC 2 CC8.1. Req 6.2.1 overlaps with HIPAA 164.308(a)(1)(i).

### Requirement 8: Identify and Authenticate

| Control | Requirement | How We Check | Status |
|---------|-------------|-------------|--------|
| 8.2.4 | MFA for admin access | Manual — code review of auth flow | Manual |
| 8.3.2 | Strong password hashing | `security_scanner.py` (password hashing detection) | Partial |
| 8.3.4 | Session timeout | Manual — code review of session config | Manual |

### Requirements 10 & 11: Logging and Testing

| Control | Requirement | How We Check | Status |
|---------|-------------|-------------|--------|
| 10.2.1 | Audit trails for auth events | Manual — logging infrastructure review | Manual |
| 10.4.1 | Time-synchronized logs | Manual review | Manual |
| 11.4.3 | DAST/SAST at least annually | `security_scanner.py`, HTTP modules | Automated |

---

## HIPAA Security Rule

### 164.312(a)(1): Unique User Identification

| Requirement | How We Check | Status |
|-------------|-------------|--------|
| Assign unique user IDs for PHI access | Manual — identity provider configuration | Manual |

### 164.312(b): Audit Controls

| Requirement | How We Check | Status |
|-------------|-------------|--------|
| Record and examine activity in systems with PHI | Manual — logging infrastructure review | Manual |

### 164.312(d): Person or Entity Authentication

| Requirement | How We Check | Status |
|-------------|-------------|--------|
| Authentication mechanisms for PHI access | `auth` module | Automated |
| MFA for remote PHI access | Manual — code review of auth flow | Manual |

### 164.312(e)(1): Transmission Security

| Requirement | How We Check | Status |
|-------------|-------------|--------|
| Encrypt PHI over electronic networks | `ssl_tls` module (TLS check) | Automated |

**Cross-framework overlap:** 164.312(e)(1) overlaps with SOC 2 CC6.7 and PCI-DSS Req 4.

---

## GDPR

### Article 25: Data Protection by Design and Default

| Requirement | How We Check | Status |
|-------------|-------------|--------|
| Implement data protection principles in system design | Manual — privacy impact assessment | Manual |
| Only process data necessary for purpose | Manual — data flow review | Manual |

### Article 32: Security of Processing

| Requirement | How We Check | Status |
|-------------|-------------|--------|
| Encryption and pseudonymization | `ssl_tls` module, `security_scanner.py` | Automated |
| Confidentiality, integrity, availability | HTTP modules (headers, auth, injection) | Automated |
| Incident response process | See `references/vulnerability_management_guide.md` | Manual |

### Article 33: Breach Notification

| Requirement | How We Check | Status |
|-------------|-------------|--------|
| Notify supervisory authority within 72 hours | Manual — incident response process | Manual |

### Article 17: Right to Erasure

| Requirement | How We Check | Status |
|-------------|-------------|--------|
| Delete personal data on request | Manual — application logic review | Manual |

### Article 20: Data Portability

| Requirement | How We Check | Status |
|-------------|-------------|--------|
| Export personal data in machine-readable format | Manual — application logic review | Manual |

---

## Tool Mapping

| Framework | Control | Requirement | Checked By | Status |
|-----------|---------|-------------|-----------|--------|
| SOC 2 | CC6.1 | Logical access controls | `auth`, `authz` modules | Automated |
| SOC 2 | CC6.7 | Encryption in transit | `ssl_tls` module | Automated |
| SOC 2 | CC7.4 | Vulnerability monitoring | `vulnerability_assessor.py` | Automated |
| PCI-DSS | 4.2.1 | TLS 1.2+ encryption | `ssl_tls` module | Automated |
| PCI-DSS | 6.2.1 | Timely software updates | `vulnerability_assessor.py` | Automated |
| PCI-DSS | 6.3.2 | SAST for custom code | `security_scanner.py` | Automated |
| PCI-DSS | 11.4.3 | DAST/SAST testing | HTTP modules + `security_scanner.py` | Automated |
| HIPAA | 164.312(d) | Person authentication | `auth` module | Automated |
| HIPAA | 164.312(e)(1) | Transmission encryption | `ssl_tls` module | Automated |
| GDPR | Art 32 | Security of processing | HTTP modules + `security_scanner.py` | Automated |
| GDPR | Art 33 | Breach notification | — | Manual review |
| GDPR | Art 17/20 | Erasure / portability | — | Manual review |

---

## References

- [SOC 2 Trust Services Criteria (2023)](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
- [PCI-DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
- [HIPAA Security Rule (45 CFR § 164.312)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C)
- [GDPR (Regulation (EU) 2016/679)](https://gdpr.eu/)
- [NIST SP 800-53 Rev 5: Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
