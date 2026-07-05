"""Authorization testing module — IDOR, forced browsing, privilege escalation."""
from collections import namedtuple

import requests
from websec_test.client.session import SessionClient
from websec_test.config.payloads import COMMON_PATHS
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])


class AuthorizationModule:
    """Test for authorization vulnerabilities: forced browsing, IDOR."""

    # Keywords in body that suggest a 404/error page rather than real content
    _404_BODY_KEYWORDS = ["not found", "404", "page not found", "error 404"]

    def discover(self, client: SessionClient, target: str):
        """Return the root endpoint to start from."""
        return [Endpoint(url="/", method="GET")]

    def _guess_user_id_patterns(self, client: SessionClient, target: str) -> list[str]:
        """Try to find IDOR-accessible user endpoints."""
        candidates = []
        for uid in [1, 2, 3]:
            for pattern in [f"/user/{uid}", f"/profile/{uid}", f"/account/{uid}"]:
                try:
                    resp = client.get(pattern)
                except requests.exceptions.RequestException:
                    continue
                if resp.status_code == 200 and len(resp.text) > 50:
                    candidates.append(pattern)
        return candidates

    def _is_likely_404(self, resp) -> bool:
        """Check if a 200 response is likely a custom 404 page."""
        if resp.status_code == 404:
            return True
        body_lower = resp.text.lower()
        return any(kw in body_lower for kw in self._404_BODY_KEYWORDS)

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Legacy test method — kept for ModuleAdapter backward compat."""
        results = []
        for path in COMMON_PATHS:
            ep = Endpoint(url=path, method="GET")
            results.append(self.check_forced_browsing(client, target, ep))
        results.append(self.check_idor_check(client, target, endpoints[0]))
        return results

    def check_forced_browsing(self, client, target, endpoint):
        path = getattr(endpoint, 'url', str(endpoint))
        try:
            resp = client.get(path)
        except requests.exceptions.RequestException as e:
            return TestResult(module="authz", test_name="forced_browsing",
                status=TestStatus.ERROR, severity=Severity.HIGH, endpoint=path,
                evidence=f"Request failed: {e}",
                recommendation="Check server availability")
        if resp.status_code == 200 and len(resp.text) > 50 and not self._is_likely_404(resp):
            return TestResult(module="authz", test_name="forced_browsing",
                status=TestStatus.FAIL, severity=Severity.HIGH, endpoint=path,
                evidence=f"Accessible: {resp.status_code}, content length: {len(resp.text)}",
                recommendation=f"Restrict access to {path} with authentication and authorization checks")
        return TestResult(module="authz", test_name="forced_browsing",
            status=TestStatus.PASS, severity=Severity.HIGH, endpoint=path,
            evidence=f"Blocked: {resp.status_code}",
            recommendation="No action needed")

    def check_idor_check(self, client, target, endpoint):
        user_endpoints = self._guess_user_id_patterns(client, target)
        if user_endpoints:
            return TestResult(module="authz", test_name="idor_check",
                status=TestStatus.FAIL, severity=Severity.CRITICAL, endpoint=str(user_endpoints),
                evidence=f"Sequential user endpoints accessible without auth: {user_endpoints}",
                recommendation="Implement proper access control checks on all user-specific endpoints")
        return TestResult(module="authz", test_name="idor_check",
            status=TestStatus.PASS, severity=Severity.CRITICAL, endpoint="/user/{id}",
            evidence="No sequential user endpoints discovered",
            recommendation="No action needed")

