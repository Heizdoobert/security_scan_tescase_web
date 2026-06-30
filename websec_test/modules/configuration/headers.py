"""Security headers test module."""
from collections import namedtuple

from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])

HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
    },
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "recommendation": "Add a Content-Security-Policy header to prevent XSS and data injection",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking",
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "recommendation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "recommendation": "Add 'Permissions-Policy' header to restrict browser feature access",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": Severity.MEDIUM,
        "recommendation": "Add 'Cross-Origin-Opener-Policy: same-origin' to prevent cross-origin opener leaks",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": Severity.MEDIUM,
        "recommendation": "Add 'Cross-Origin-Resource-Policy: same-origin' to restrict resource loading from other origins",
    },
}


class HeadersModule:
    """Check for missing security headers on the target root page."""

    def discover(self, client: SessionClient, target: str):
        """Return the root endpoint to test."""
        return [Endpoint(url="/", method="GET")]

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Check each endpoint for required security headers."""
        results = []
        for ep in endpoints:
            try:
                resp = client.get(ep.url)
            except requests.exceptions.RequestException as e:
                for header, info in HEADER_CHECKS.items():
                    results.append(TestResult(
                        module="headers",
                        test_name=f"check_{header.replace('-', '_').lower()}",
                        status=TestStatus.ERROR,
                        severity=info["severity"],
                        endpoint=ep.url,
                        evidence=f"Request failed: {e}",
                        recommendation=info["recommendation"],
                    ))
                continue
            for header, info in HEADER_CHECKS.items():
                if header in resp.headers:
                    status = TestStatus.PASS
                    evidence = f"{header}: {resp.headers[header]}"
                else:
                    status = TestStatus.FAIL
                    evidence = f"Missing '{header}' header"
                results.append(TestResult(
                    module="headers",
                    test_name=f"check_{header.replace('-', '_').lower()}",
                    status=status,
                    severity=info["severity"],
                    endpoint=ep.url,
                    evidence=evidence,
                    recommendation=info["recommendation"],
                ))
        return results

