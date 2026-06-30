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
        """Legacy test method — kept for ModuleAdapter backward compat."""
        return [r for ep in endpoints for r in [
            self.check_wildcard_origin(client, target, ep),
            self.check_credentials_with_wildcard(client, target, ep),
            self.check_reflected_origin(client, target, ep),
        ]]

    def check_wildcard_origin(self, client, target, endpoint):
        ep_url = getattr(endpoint, 'url', str(endpoint))
        resp = client.get(ep_url, headers={"Origin": "https://evil.com"})
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            return TestResult(module="cors", test_name="wildcard_origin",
                status=TestStatus.FAIL, severity=Severity.HIGH, endpoint=ep_url,
                evidence="Access-Control-Allow-Origin: * allows any site",
                recommendation="Restrict ACAO to specific trusted origins, not wildcard")
        elif acao == "https://evil.com":
            return TestResult(module="cors", test_name="wildcard_origin",
                status=TestStatus.FAIL, severity=Severity.HIGH, endpoint=ep_url,
                evidence="Origin 'https://evil.com' echoed back in ACAO",
                recommendation="Validate Origin against a whitelist, do not echo it back")
        return TestResult(module="cors", test_name="wildcard_origin",
            status=TestStatus.PASS, severity=Severity.HIGH, endpoint=ep_url,
            evidence=f"ACAO: {acao or '(not set)'}",
            recommendation="No action needed")

    def check_credentials_with_wildcard(self, client, target, endpoint):
        ep_url = getattr(endpoint, 'url', str(endpoint))
        resp = client.get(ep_url, headers={"Origin": "https://evil.com"})
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            return TestResult(module="cors", test_name="credentials_with_wildcard",
                status=TestStatus.FAIL, severity=Severity.CRITICAL, endpoint=ep_url,
                evidence="Access-Control-Allow-Credentials: true with wildcard origin",
                recommendation="Cannot use wildcard origin with credentials. Use specific origin.")
        return TestResult(module="cors", test_name="credentials_with_wildcard",
            status=TestStatus.PASS, severity=Severity.CRITICAL, endpoint=ep_url,
            evidence=f"ACAC: {acac or '(not set)'}, ACAO: {acao or '(not set)'}",
            recommendation="No action needed")

    def check_reflected_origin(self, client, target, endpoint):
        ep_url = getattr(endpoint, 'url', str(endpoint))
        resp = client.get(ep_url, headers={"Origin": "https://attacker.com"})
        acao2 = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao2 == "https://attacker.com":
            return TestResult(module="cors", test_name="reflected_origin",
                status=TestStatus.FAIL, severity=Severity.HIGH, endpoint=ep_url,
                evidence="Server reflects arbitrary Origin headers",
                recommendation="Whitelist allowed origins instead of reflecting")
        return TestResult(module="cors", test_name="reflected_origin",
            status=TestStatus.PASS, severity=Severity.HIGH, endpoint=ep_url,
            evidence=f"Origin not reflected: {acao2 or '(not set)'}",
            recommendation="No action needed")

