# Responsible Disclosure Policy

> Guidelines for security researchers and pen-testers reporting vulnerabilities.

## Disclosure Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| Initial Report | Day 0 | Researcher submits finding via secure channel |
| Acknowledgment | 24 hours | Vendor confirms receipt of report |
| Triage | 3 business days | Vendor validates and classifies severity |
| Fix Window | 30-90 days | Vendor develops and deploys patch (90-day default for critical/high) |
| Public Disclosure | Day 90+ | Researcher publishes after patch deploy |

### Extended Timeline
If remediation requires a major architectural change (e.g., authentication overhaul), the vendor may request a 30-day extension (120 days total). The researcher should grant one extension if the vendor provides a written remediation plan with milestones.

## Communication Templates

### Initial Report
```
Subject: Security Vulnerability Report — [PRODUCT] — [SUMMARY]

Vulnerability Type: [CWE ID]
Affected Component: [URL / endpoint / module]
Severity: [CVSS Score — Critical/High/Medium/Low]

Description:
[2-3 paragraphs describing the vulnerability, impact, and attack scenario]

Steps to Reproduce:
1. [Step 1]
2. [Step 2]
3. [Step 3]

Proof of Concept:
[Minimal reproduction, redacted to prevent abuse]

Suggested Remediation:
[Brief recommendation]

Disclosure Preference:
[ ] 90-day standard timeline
[ ] Extended timeline (120 days, reason: [])
```

### Vendor Acknowledgment
```
Subject: Re: Security Vulnerability Report — [PRODUCT]

Thank you for your report. We have received it and assigned tracking ID [ID].

Next steps:
1. Triage: [Date] (within 3 business days)
2. Fix target: [Date]
3. Coordinated disclosure: [Date]

We will provide updates at each milestone. For critical-severity findings,
we may request a 30-day extension with a written remediation plan.

Contact: [security@company.com]
```

### 90-Day Reminder
```
Subject: Disclosure Timeline — [VULNERABILITY] — Day 75

This is a 15-day notice that the 90-day disclosure window for [VULNERABILITY]
closes on [DATE].

Current status:
- Fix deployed: [Yes/No]
- Patch version: [Version / Not applicable / Not yet]
- CVE assigned: [CVE ID / Not yet]

If the patch is not deployed by Day 90, we intend to publish our findings
on [DATE] per our responsible disclosure policy.
```

## Safe Harbor

We commit to:
- Not pursue legal action against researchers who follow this policy
- Not request DMCA takedown of published research that follows the timeline
- Publicly credit researchers who submit valid reports (with consent)

Researchers must:
- Access only systems explicitly within scope
- Not exfiltrate or modify user data beyond proof of concept
- Report findings immediately, not after exploitation
- Not demand payment (this is NOT a bug bounty program)

## References

- ISO 29147: Vulnerability Disclosure
- CERT/CC Vulnerability Disclosure Policy
- Google Project Zero Disclosure Policy
