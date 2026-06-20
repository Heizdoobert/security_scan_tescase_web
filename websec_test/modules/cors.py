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
