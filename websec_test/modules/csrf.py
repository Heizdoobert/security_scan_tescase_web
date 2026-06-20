"""CSRF (Cross-Site Request Forgery) test module."""
import re
from collections import namedtuple
from urllib.parse import urljoin

import requests
from websec_test.client.session import SessionClient
from websec_test.engine.builder import CheckSpec
from websec_test.engine.registry import register
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


# ── Check-level BT support ──────────────────────────────────────────────


def _check_missing_csrf_token_fn(client, target, blackboard):
    """Discover POST forms and check for CSRF token presence."""
    import re
    from urllib.parse import urljoin

    resp = client.get("/")
    pattern = re.compile(
        r'<form[^>]*method=["\'](post|POST)["\'][^>]*>.*?</form>',
        re.DOTALL | re.IGNORECASE
    )
    forms_found = 0
    for form_match in pattern.finditer(resp.text):
        form_html = form_match.group(0)
        action_match = re.search(r'action=["\']([^"\']+)', form_html)
        action = action_match.group(1) if action_match else "/"
        fields = re.findall(r'<input[^>]*name=["\']([^"\']+)[^>]*>', form_html)
        full_url = urljoin(target + "/", action.lstrip("/"))
        forms_found += 1

        token = client.extract_csrf_token(resp.text)
        if not token:
            return TestResult(
                module="csrf", test_name="missing_csrf_token",
                status=TestStatus.FAIL, severity=Severity.HIGH,
                endpoint=full_url,
                evidence="No CSRF token found in any form field",
                recommendation="Add CSRF token to all state-changing POST forms",
            )
    if forms_found == 0:
        return TestResult(
            module="csrf", test_name="missing_csrf_token",
            status=TestStatus.PASS, severity=Severity.HIGH,
            endpoint="/", evidence="No POST forms found on page",
            recommendation="No action needed",
        )
    return TestResult(
        module="csrf", test_name="missing_csrf_token",
        status=TestStatus.PASS, severity=Severity.HIGH,
        endpoint="/", evidence="CSRF token found on all POST forms",
        recommendation="No action needed",
    )


def _check_csrf_token_reuse_fn(client, target, blackboard):
    """Discover POST forms and test if CSRF tokens can be reused."""
    import re
    from urllib.parse import urljoin

    import requests as req_lib

    resp = client.get("/")
    pattern = re.compile(
        r'<form[^>]*method=["\'](post|POST)["\'][^>]*>.*?</form>',
        re.DOTALL | re.IGNORECASE
    )
    CSRF_FIELD_NAMES = ["csrf_token", "_token", "authenticity_token", "csrfmiddlewaretoken"]

    for form_match in pattern.finditer(resp.text):
        form_html = form_match.group(0)
        action_match = re.search(r'action=["\']([^"\']+)', form_html)
        action = action_match.group(1) if action_match else "/"
        fields = re.findall(r'<input[^>]*name=["\']([^"\']+)[^>]*>', form_html)
        full_url = urljoin(target + "/", action.lstrip("/"))

        token = client.extract_csrf_token(resp.text)
        if not token:
            continue

        csrf_field = next((f for f in fields if f in CSRF_FIELD_NAMES), "csrf_token")
        data = {f: "test" for f in fields if f not in CSRF_FIELD_NAMES}
        try:
            r1 = client.post(full_url, data=data | {csrf_field: token})
            r2 = client.post(full_url, data=data | {csrf_field: token})
        except req_lib.exceptions.RequestException as e:
            return TestResult(
                module="csrf", test_name="csrf_token_reuse",
                status=TestStatus.ERROR, severity=Severity.HIGH,
                endpoint=full_url,
                evidence=f"Request failed during reuse test: {e}",
                recommendation="Check server availability and try again",
            )
        if r1.status_code == 200 and r2.status_code == 200:
            return TestResult(
                module="csrf", test_name="csrf_token_reuse",
                status=TestStatus.FAIL, severity=Severity.HIGH,
                endpoint=full_url,
                evidence=f"Same token reused ({r1.status_code}, {r2.status_code})",
                recommendation="Invalidate CSRF token after each use",
            )

    return TestResult(
        module="csrf", test_name="csrf_token_reuse",
        status=TestStatus.PASS, severity=Severity.HIGH,
        endpoint="/", evidence="Token reuse rejected or no forms to test",
        recommendation="No action needed",
    )


@register("csrf")
def csrf_check_specs():
    return [
        CheckSpec("missing_csrf_token", _check_missing_csrf_token_fn,
                  severity=Severity.HIGH, module_name="csrf"),
        CheckSpec("csrf_token_reuse", _check_csrf_token_reuse_fn,
                  severity=Severity.HIGH, module_name="csrf"),
    ]
