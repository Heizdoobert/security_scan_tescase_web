"""Security headers test module."""
from collections import namedtuple

import requests
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
        """Legacy test method — kept for ModuleAdapter backward compat."""
        return [self._check_single(client, target, ep, header, info)
                for ep in endpoints
                for header, info in HEADER_CHECKS.items()]

    def _check_single(self, client, target, endpoint, header, info):
        try:
            resp = client.get(getattr(endpoint, 'url', str(endpoint)))
        except Exception as e:
            return TestResult(module="headers",
                test_name=f"check_{header.replace('-', '_').lower()}",
                status=TestStatus.ERROR, severity=info["severity"],
                endpoint=getattr(endpoint, 'url', str(endpoint)),
                evidence=f"Request failed: {e}", recommendation=info["recommendation"])
        if header in resp.headers:
            return TestResult(module="headers",
                test_name=f"check_{header.replace('-', '_').lower()}",
                status=TestStatus.PASS, severity=info["severity"],
                endpoint=getattr(endpoint, 'url', str(endpoint)),
                evidence=f"{header}: {resp.headers[header]}", recommendation=info["recommendation"])
        return TestResult(module="headers",
            test_name=f"check_{header.replace('-', '_').lower()}",
            status=TestStatus.FAIL, severity=info["severity"],
            endpoint=getattr(endpoint, 'url', str(endpoint)),
            evidence=f"Missing '{header}' header", recommendation=info["recommendation"])

    def check_strict_transport_security(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Strict-Transport-Security", HEADER_CHECKS["Strict-Transport-Security"])
    def check_content_security_policy(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Content-Security-Policy", HEADER_CHECKS["Content-Security-Policy"])
    def check_x_frame_options(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "X-Frame-Options", HEADER_CHECKS["X-Frame-Options"])
    def check_x_content_type_options(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "X-Content-Type-Options", HEADER_CHECKS["X-Content-Type-Options"])
    def check_referrer_policy(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Referrer-Policy", HEADER_CHECKS["Referrer-Policy"])
    def check_permissions_policy(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Permissions-Policy", HEADER_CHECKS["Permissions-Policy"])
    def check_cross_origin_opener_policy(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Cross-Origin-Opener-Policy", HEADER_CHECKS["Cross-Origin-Opener-Policy"])
    def check_cross_origin_resource_policy(self, client, target, endpoint):
        return self._check_single(client, target, endpoint, "Cross-Origin-Resource-Policy", HEADER_CHECKS["Cross-Origin-Resource-Policy"])

