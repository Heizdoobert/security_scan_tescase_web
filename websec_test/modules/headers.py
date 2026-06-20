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


# ── Check-level BT support ──────────────────────────────────────────────

from websec_test.engine.registry import register
from websec_test.engine.builder import CheckSpec


def _check_single_header(client, target, blackboard, header_name, info):
    """Check if a single security header is present.

    Reads endpoints from blackboard (set by DiscoverAction).
    """
    endpoints = blackboard.get("headers_discover_endpoints", None)
    if not endpoints:
        return TestResult(
            module="headers",
            test_name=f"check_{header_name.replace('-', '_').lower()}",
            status=TestStatus.ERROR,
            severity=info["severity"],
            endpoint=target,
            evidence="No endpoints discovered",
            recommendation=info["recommendation"],
        )
    ep = endpoints[0]
    try:
        resp = client.get(ep.url)
    except requests.exceptions.RequestException as e:
        return TestResult(
            module="headers",
            test_name=f"check_{header_name.replace('-', '_').lower()}",
            status=TestStatus.ERROR,
            severity=info["severity"],
            endpoint=ep.url,
            evidence=f"Request failed: {e}",
            recommendation=info["recommendation"],
        )
    present = header_name in resp.headers
    status = TestStatus.PASS if present else TestStatus.FAIL
    evidence = f"{header_name}: {resp.headers.get(header_name, 'MISSING')}"
    return TestResult(
        module="headers",
        test_name=f"check_{header_name.replace('-', '_').lower()}",
        status=status,
        severity=info["severity"],
        endpoint=ep.url,
        evidence=evidence,
        recommendation=info["recommendation"],
    )


@register("headers")
def headers_check_specs():
    """Build CheckSpec list for headers module."""
    from functools import partial
    result = []
    for header, info in HEADER_CHECKS.items():
        fn = partial(_check_single_header, header_name=header, info=info)
        fn.__name__ = f"check_{header.replace('-', '_').lower()}"
        result.append(CheckSpec(
            name=f"check_{header.replace('-', '_').lower()}",
            fn=fn,
            severity=info["severity"],
            module_name="headers",
        ))
    return result
