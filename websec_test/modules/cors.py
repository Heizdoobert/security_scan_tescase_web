"""CORS (Cross-Origin Resource Sharing) security test module.

Checks for permissive CORS policies that could allow cross-origin data theft.
"""
from collections import namedtuple

from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])


class CorsModule:
    """Test for CORS misconfigurations: wildcard origins, credential exposure."""

    def discover(self, client: SessionClient, target: str):
        """Return the root endpoint to test with a malicious origin."""
        return [Endpoint(url="/", method="GET")]

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Send requests with a spoofed Origin header and inspect CORS headers."""
        results = []
        malicious_origin = "https://evil.com"

        for ep in endpoints:
            resp = client.get(ep.url, headers={"Origin": malicious_origin})
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            # Test: wildcard origin
            if acao == "*":
                results.append(TestResult(
                    module="cors", test_name="wildcard_origin",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=ep.url,
                    evidence=f"Access-Control-Allow-Origin: * allows any site",
                    recommendation="Restrict ACAO to specific trusted origins, not wildcard",
                ))
            elif acao == malicious_origin:
                results.append(TestResult(
                    module="cors", test_name="wildcard_origin",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=ep.url,
                    evidence=f"Origin '{malicious_origin}' echoed back in ACAO",
                    recommendation="Validate Origin against a whitelist, do not echo it back",
                ))
            else:
                results.append(TestResult(
                    module="cors", test_name="wildcard_origin",
                    status=TestStatus.PASS, severity=Severity.HIGH,
                    endpoint=ep.url,
                    evidence=f"ACAO: {acao or '(not set)'}",
                    recommendation="No action needed",
                ))

            # Test: credentials with wildcard
            if acao == "*" and acac.lower() == "true":
                results.append(TestResult(
                    module="cors", test_name="credentials_with_wildcard",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=ep.url,
                    evidence="Access-Control-Allow-Credentials: true with wildcard origin",
                    recommendation="Cannot use wildcard origin with credentials. Use specific origin.",
                ))
            else:
                results.append(TestResult(
                    module="cors", test_name="credentials_with_wildcard",
                    status=TestStatus.PASS, severity=Severity.CRITICAL,
                    endpoint=ep.url,
                    evidence=f"ACAC: {acac or '(not set)'}, ACAO: {acao or '(not set)'}",
                    recommendation="No action needed",
                ))

            # Test: reflected origin (server echoes back any Origin)
            resp2 = client.get(ep.url, headers={"Origin": "https://attacker.com"})
            acao2 = resp2.headers.get("Access-Control-Allow-Origin", "")
            if acao2 == "https://attacker.com":
                results.append(TestResult(
                    module="cors", test_name="reflected_origin",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=ep.url,
                    evidence="Server reflects arbitrary Origin headers",
                    recommendation="Whitelist allowed origins instead of reflecting",
                ))
            else:
                results.append(TestResult(
                    module="cors", test_name="reflected_origin",
                    status=TestStatus.PASS, severity=Severity.HIGH,
                    endpoint=ep.url,
                    evidence=f"Origin not reflected: {acao2 or '(not set)'}",
                    recommendation="No action needed",
                ))

        return results


# ── Check-level BT support ──────────────────────────────────────────────

from websec_test.engine.registry import register
from websec_test.engine.builder import CheckSpec

MALICIOUS_ORIGIN = "https://evil.com"


def _check_wildcard_origin_fn(client, target, blackboard):
    """Check for wildcard or echoed Access-Control-Allow-Origin."""
    endpoints = blackboard.get("cors_discover_endpoints", None)
    if not endpoints:
        return TestResult(
            module="cors", test_name="wildcard_origin",
            status=TestStatus.ERROR, severity=Severity.HIGH,
            endpoint=target, evidence="No endpoints discovered",
            recommendation="Restrict ACAO to specific trusted origins",
        )
    ep = endpoints[0]
    resp = client.get(ep.url, headers={"Origin": MALICIOUS_ORIGIN})
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        return TestResult(
            module="cors", test_name="wildcard_origin",
            status=TestStatus.FAIL, severity=Severity.HIGH,
            endpoint=ep.url,
            evidence="Access-Control-Allow-Origin: * allows any site",
            recommendation="Restrict ACAO to specific trusted origins, not wildcard",
        )
    elif acao == MALICIOUS_ORIGIN:
        return TestResult(
            module="cors", test_name="wildcard_origin",
            status=TestStatus.FAIL, severity=Severity.HIGH,
            endpoint=ep.url,
            evidence=f"Origin '{MALICIOUS_ORIGIN}' echoed back in ACAO",
            recommendation="Validate Origin against a whitelist, do not echo it back",
        )
    return TestResult(
        module="cors", test_name="wildcard_origin",
        status=TestStatus.PASS, severity=Severity.HIGH,
        endpoint=ep.url,
        evidence=f"ACAO: {acao or '(not set)'}",
        recommendation="No action needed",
    )


def _check_credentials_with_wildcard_fn(client, target, blackboard):
    """Check for wildcard ACAO with ACAC: true."""
    endpoints = blackboard.get("cors_discover_endpoints", None)
    if not endpoints:
        return TestResult(
            module="cors", test_name="credentials_with_wildcard",
            status=TestStatus.ERROR, severity=Severity.CRITICAL,
            endpoint=target, evidence="No endpoints discovered",
            recommendation="Cannot use wildcard origin with credentials",
        )
    ep = endpoints[0]
    resp = client.get(ep.url, headers={"Origin": MALICIOUS_ORIGIN})
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and acac.lower() == "true":
        return TestResult(
            module="cors", test_name="credentials_with_wildcard",
            status=TestStatus.FAIL, severity=Severity.CRITICAL,
            endpoint=ep.url,
            evidence="Access-Control-Allow-Credentials: true with wildcard origin",
            recommendation="Cannot use wildcard origin with credentials. Use specific origin.",
        )
    return TestResult(
        module="cors", test_name="credentials_with_wildcard",
        status=TestStatus.PASS, severity=Severity.CRITICAL,
        endpoint=ep.url,
        evidence=f"ACAC: {acac or '(not set)'}, ACAO: {acao or '(not set)'}",
        recommendation="No action needed",
    )


def _check_reflected_origin_fn(client, target, blackboard):
    """Check if the server reflects arbitrary Origin headers."""
    endpoints = blackboard.get("cors_discover_endpoints", None)
    if not endpoints:
        return TestResult(
            module="cors", test_name="reflected_origin",
            status=TestStatus.ERROR, severity=Severity.HIGH,
            endpoint=target, evidence="No endpoints discovered",
            recommendation="Whitelist allowed origins instead of reflecting",
        )
    ep = endpoints[0]
    attacker = "https://attacker.com"
    resp = client.get(ep.url, headers={"Origin": attacker})
    acao2 = resp.headers.get("Access-Control-Allow-Origin", "")
    if acao2 == attacker:
        return TestResult(
            module="cors", test_name="reflected_origin",
            status=TestStatus.FAIL, severity=Severity.HIGH,
            endpoint=ep.url,
            evidence="Server reflects arbitrary Origin headers",
            recommendation="Whitelist allowed origins instead of reflecting",
        )
    return TestResult(
        module="cors", test_name="reflected_origin",
        status=TestStatus.PASS, severity=Severity.HIGH,
        endpoint=ep.url,
        evidence=f"Origin not reflected: {acao2 or '(not set)'}",
        recommendation="No action needed",
    )


@register("cors")
def cors_check_specs():
    return [
        CheckSpec("wildcard_origin", _check_wildcard_origin_fn,
                  severity=Severity.HIGH, module_name="cors"),
        CheckSpec("credentials_with_wildcard", _check_credentials_with_wildcard_fn,
                  severity=Severity.CRITICAL, module_name="cors"),
        CheckSpec("reflected_origin", _check_reflected_origin_fn,
                  severity=Severity.HIGH, module_name="cors"),
    ]
