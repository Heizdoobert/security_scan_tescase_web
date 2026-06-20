"""CSRF (Cross-Site Request Forgery) test module."""
import re
from collections import namedtuple
from urllib.parse import urljoin

import requests
from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method", "form_action", "fields"])


class CSRFModule:
    """Test forms for CSRF token presence and validation."""

    CSRF_FIELD_NAMES = ["csrf_token", "_token", "authenticity_token", "csrfmiddlewaretoken"]

    @staticmethod
    def _detect_csrf_field_name(fields: list[str]) -> str:
        for f in fields:
            if f in CSRFModule.CSRF_FIELD_NAMES:
                return f
        return "csrf_token"

    def _extract_forms(self, html: str, base_url: str) -> list[Endpoint]:
        """Parse HTML for POST forms and their fields."""
        forms = []
        pattern = re.compile(
            r'<form[^>]*method=["\'](post|POST)["\'][^>]*>.*?</form>',
            re.DOTALL | re.IGNORECASE
        )
        for form_match in pattern.finditer(html):
            form_html = form_match.group(0)
            action_match = re.search(r'action=["\']([^"\']+)', form_html)
            action = action_match.group(1) if action_match else base_url
            fields = re.findall(r'<input[^>]*name=["\']([^"\']+)[^>]*>', form_html)
            full_url = urljoin(base_url + "/", action.lstrip("/"))
            forms.append(Endpoint(url=full_url, method="POST", form_action=action, fields=fields))
        return forms

    def discover(self, client: SessionClient, target: str):
        """Scan the target root page for POST forms."""
        resp = client.get("/")
        return self._extract_forms(resp.text, target)

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        results = []
        for ep in endpoints:
            resp = client.get(ep.url)
            token = client.extract_csrf_token(resp.text)

            if token:
                results.append(TestResult(
                    module="csrf",
                    test_name="missing_csrf_token",
                    status=TestStatus.PASS,
                    severity=Severity.HIGH,
                    endpoint=ep.url,
                    evidence=f"CSRF token found: {token[:20]}...",
                    recommendation="No action needed",
                ))
                # Test: token reuse — use the actual CSRF field name from the form
                data = {field: "test" for field in ep.fields if field not in CSRFModule.CSRF_FIELD_NAMES}
                csrf_field_name = self._detect_csrf_field_name(ep.fields)
                try:
                    r1 = client.post(ep.url, data=data | {csrf_field_name: token})
                    r2 = client.post(ep.url, data=data | {csrf_field_name: token})
                except requests.exceptions.RequestException as e:
                    results.append(TestResult(
                        module="csrf",
                        test_name="csrf_token_reuse",
                        status=TestStatus.ERROR,
                        severity=Severity.HIGH,
                        endpoint=ep.url,
                        evidence=f"Request failed during reuse test: {e}",
                        recommendation="Check server availability and try again",
                    ))
                    continue
                if r1.status_code == 200 and r2.status_code == 200:
                    results.append(TestResult(
                        module="csrf",
                        test_name="csrf_token_reuse",
                        status=TestStatus.FAIL,
                        severity=Severity.HIGH,
                        endpoint=ep.url,
                        evidence=f"Same token '{token[:20]}...' accepted twice ({r1.status_code}, {r2.status_code})",
                        recommendation="Invalidate CSRF token after each use",
                    ))
                else:
                    results.append(TestResult(
                        module="csrf",
                        test_name="csrf_token_reuse",
                        status=TestStatus.PASS,
                        severity=Severity.HIGH,
                        endpoint=ep.url,
                        evidence="Token reuse rejected",
                        recommendation="No action needed",
                    ))
            else:
                results.append(TestResult(
                    module="csrf",
                    test_name="missing_csrf_token",
                    status=TestStatus.FAIL,
                    severity=Severity.HIGH,
                    endpoint=ep.url,
                    evidence="No CSRF token found in any form field",
                    recommendation="Add CSRF token to all state-changing POST forms",
                ))
        return results
