"""Authentication and session security test module."""
import re
import time
from collections import namedtuple
from urllib.parse import urljoin

import requests
from websec_test.client.session import SessionClient
from websec_test.config.payloads import SQLI_PAYLOADS
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])

SELECTOR_GROUPS = {"sqli_techniques": ["check_sqli_login_bypass"]}


class AuthModule:
    """Test authentication mechanisms: login form discovery, bypass tests, session handling."""

    def __init__(self, credentials: str | None = None, target: str = ""):
        self.credentials = credentials
        self.target = target

    def _candidate_login_paths(self, target: str) -> list[str]:
        candidates = [target, "/note/login", "/login", "/auth", "/signin", "/Login"]
        seen = set()
        ordered = []
        for candidate in candidates:
            if candidate and candidate not in seen:
                seen.add(candidate)
                ordered.append(candidate)
        return ordered

    def discover(self, client: SessionClient, target: str):
        """Find login forms by checking common login paths."""
        self.target = target
        endpoints = []
        for path in self._candidate_login_paths(target):
            try:
                resp = client.get(path)
            except requests.exceptions.ConnectionError:
                continue
            if resp.status_code == 200 and ("password" in resp.text.lower()
                                            or "login" in resp.text.lower()
                                            or "form" in resp.text.lower()):
                endpoint_url = resp.url if path == target else path
                endpoints.append(Endpoint(url=endpoint_url, method="POST"))
        return endpoints

    def _extract_form_action(self, html: str) -> str | None:
        match = re.search(r'<form[^>]*action=["\']([^"\']+)', html, re.IGNORECASE)
        return match.group(1) if match else None

    def _build_post_url(self, client, endpoint):
        endpoint_url = getattr(endpoint, 'url', str(endpoint))
        resp = client.get(endpoint_url)
        form_action = self._extract_form_action(resp.text) or endpoint_url
        if form_action.startswith("/"):
            return endpoint_url
        return urljoin(resp.url, form_action)

    def _credentials_username(self) -> str:
        if self.credentials and ":" in self.credentials:
            return self.credentials.split(":", 1)[0]
        return self.credentials or "admin"

    def _looks_like_login_success(self, response) -> bool:
        if 300 <= response.status_code < 400:
            return True
        body = response.text.lower()
        
        # If the page shows a clear authentication error, it's not a success
        error_markers = ("username or password wrong", "incorrect password", "invalid credentials", "login failed")
        if any(err in body for err in error_markers):
            return False

        success_markers = ("dashboard", "logout", "profile")
        # 'welcome' is too generic (e.g. "Welcome back!" on the login page itself)
        
        return response.status_code == 200 and any(marker in body for marker in success_markers)

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Legacy test method — kept for ModuleAdapter backward compat."""
        results = []
        for ep in endpoints:
            results.append(self.check_sqli_login_bypass(client, target, ep))
            results.append(self.check_rate_limiting(client, target, ep))
            results.append(self.check_username_enumeration(client, target, ep))
            results.append(self.check_blank_password_login(client, target, ep))
        return results

    def check_blank_password_login(self, client, target, endpoint):
        post_url = self._build_post_url(client, endpoint)
        response = client.post(post_url, data={"username": self._credentials_username(), "password": ""})
        if self._looks_like_login_success(response):
            return TestResult(module="auth", test_name="blank_password_login",
                status=TestStatus.FAIL, severity=Severity.HIGH, endpoint=post_url,
                evidence=f"Blank password accepted ({response.status_code}): {response.text[:100]}",
                recommendation="Reject empty passwords and require credential validation")
        return TestResult(module="auth", test_name="blank_password_login",
            status=TestStatus.PASS, severity=Severity.MEDIUM, endpoint=post_url,
            evidence=f"Blank password rejected ({response.status_code})",
            recommendation="No action needed")

    def check_sqli_login_bypass(self, client, target, endpoint):
        post_url = self._build_post_url(client, endpoint)
        for payload in SQLI_PAYLOADS[:2]:
            r = client.post(post_url, data={"username": payload, "password": "test"})
            if self._looks_like_login_success(r):
                return TestResult(module="auth", test_name="sqli_login_bypass",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL, endpoint=post_url,
                    evidence=f"SQLi payload '{payload}' returned {r.status_code}: {r.text[:100]}",
                    recommendation="Sanitize all login inputs, use parameterized queries")
        return TestResult(module="auth", test_name="sqli_login_bypass",
            status=TestStatus.PASS, severity=Severity.CRITICAL, endpoint=post_url,
            evidence="SQLi payloads rejected (no successful bypass)",
            recommendation="No action needed")

    def check_rate_limiting(self, client, target, endpoint):
        post_url = self._build_post_url(client, endpoint)
        statuses = []
        for _ in range(10):
            try:
                resp = client.post(post_url, data={"username": "admin", "password": "wrong"})
                statuses.append(resp.status_code)
            except requests.exceptions.RequestException:
                statuses.append(0)
            time.sleep(0.1)
        if 429 in statuses:
            return TestResult(module="auth", test_name="rate_limiting",
                status=TestStatus.PASS, severity=Severity.HIGH, endpoint=post_url,
                evidence=f"Rate limiting detected (HTTP 429 after {statuses.count(429)}/10 requests)",
                recommendation="No action needed")
        return TestResult(module="auth", test_name="rate_limiting",
            status=TestStatus.FAIL, severity=Severity.MEDIUM, endpoint=post_url,
            evidence=f"No rate limiting detected (status codes: {set(statuses)})",
            recommendation="Implement rate limiting (e.g., HTTP 429 after N failed attempts)")

    def check_username_enumeration(self, client, target, endpoint):
        post_url = self._build_post_url(client, endpoint)
        try:
            resp_valid = client.post(post_url, data={"username": self._credentials_username(), "password": "wrongpass"})
        except requests.exceptions.RequestException as e:
            return TestResult(module="auth", test_name="username_enumeration",
                status=TestStatus.ERROR, severity=Severity.MEDIUM, endpoint=post_url,
                evidence=f"Request for valid username failed: {e}",
                recommendation="Check server availability and try again")
        try:
            resp_invalid = client.post(post_url, data={"username": "thisuserdoesnotexist_xyz", "password": "wrongpass"})
        except requests.exceptions.RequestException as e:
            return TestResult(module="auth", test_name="username_enumeration",
                status=TestStatus.ERROR, severity=Severity.MEDIUM, endpoint=post_url,
                evidence=f"Request for invalid username failed: {e}",
                recommendation="Check server availability and try again")
        if resp_valid.text != resp_invalid.text:
            return TestResult(module="auth", test_name="username_enumeration",
                status=TestStatus.FAIL, severity=Severity.MEDIUM, endpoint=post_url,
                evidence="Different responses for valid vs invalid usernames (possible enumeration)",
                recommendation="Return consistent error messages for both valid and invalid usernames")
        return TestResult(module="auth", test_name="username_enumeration",
            status=TestStatus.PASS, severity=Severity.MEDIUM, endpoint=post_url,
            evidence="Identical responses for valid and invalid usernames",
            recommendation="No action needed")


