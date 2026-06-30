"""NoSQL injection testing module.

Tests for NoSQL injection via MongoDB operator payloads in three formats:
URL-encoded (PHP-style), JSON body, and raw query string.
"""
from urllib.parse import urlencode

from websec_test.client.session import SessionClient
from websec_test.config.payloads import NOSQLI_PAYLOADS
from websec_test.modules._shared import Endpoint, parse_form_inputs
from websec_test.results.models import TestResult, TestStatus, Severity


class NosqlModule:
    """Test for NoSQL injection vulnerabilities using MongoDB operators."""

    def _extract_form_inputs(self, html: str) -> list[Endpoint]:
        return [Endpoint(url=ep["url"], method="GET", param_names=ep["param_names"])
                for ep in parse_form_inputs(html)]

    def discover(self, client: SessionClient, target: str):
        resp = client.get(target.rstrip("/") + "/")
        return self._extract_form_inputs(resp.text)

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        return self._test_nosqli(client, target, endpoints)

    def _test_nosqli(self, client: SessionClient, target: str, endpoints):
        import requests
        results = []
        bypass_keywords = ["welcome", "dashboard", "login successful",
                           "logged in", "authenticated", "success"]

        for ep in endpoints:
            for param in ep.param_names:
                base_url = f"{target.rstrip('/')}{ep.url}"
                baseline_url = f"{base_url}?{urlencode({param: 'invalid__test__value'})}"
                try:
                    baseline = client.get(baseline_url)
                    baseline_len = len(baseline.text)
                except requests.exceptions.ConnectionError:
                    continue

                def url_encoded_req(p):
                    url = f"{base_url}?{self._php_style_params(param, p)}"
                    return client.get(url), url

                result = self._try_nosql_format(
                    client, NOSQLI_PAYLOADS["auth_bypass"],
                    url_encoded_req, baseline_len, baseline.text,
                    bypass_keywords, "URL-encoded",
                )
                if result:
                    results.append(result)
                    continue

                def json_body_req(p):
                    return (
                        client.post(base_url, json={param: p},
                                    headers={"Content-Type": "application/json"}),
                        base_url,
                    )

                result = self._try_nosql_format(
                    client, NOSQLI_PAYLOADS["auth_bypass"],
                    json_body_req, baseline_len, baseline.text,
                    bypass_keywords, "JSON body",
                )
                if result:
                    results.append(result)
                    continue

                def query_string_req(p):
                    params = {param: p}
                    url = f"{base_url}?{urlencode(params)}"
                    return client.get(url), url

                result = self._try_nosql_format(
                    client, NOSQLI_PAYLOADS["field_injection"],
                    query_string_req, baseline_len, baseline.text,
                    bypass_keywords, "query string",
                )
                if result:
                    results.append(result)
                    continue

                results.append(TestResult(
                    module="nosql", test_name="nosql_injection",
                    status=TestStatus.PASS, severity=Severity.CRITICAL,
                    endpoint=ep.url,
                    evidence="No NoSQL injection bypass detected",
                    recommendation="No action needed",
                ))

        return results

    @staticmethod
    def _is_nosql_bypass(resp, baseline_len, baseline_text, bypass_keywords):
        text_lower = resp.text.lower()
        if any(kw in text_lower for kw in bypass_keywords):
            return True
        if resp.status_code == 500:
            return True
        if abs(len(resp.text) - baseline_len) > 5:
            return True
        return False

    def _try_nosql_format(self, client, payloads, perform_request,
                          baseline_len, baseline_text, bypass_keywords, format_name):
        import requests
        for payload in payloads:
            op_key = list(payload.keys())[0] if payload else ""
            try:
                resp, endpoint_url = perform_request(payload)
            except (requests.exceptions.ConnectionError, requests.ConnectTimeout):
                continue
            if self._is_nosql_bypass(resp, baseline_len, baseline_text, bypass_keywords):
                return TestResult(
                    module="nosql", test_name="nosql_injection",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=endpoint_url,
                    evidence=f"NoSQL bypass via {format_name} operator '{op_key}': {resp.text[:150]}",
                    recommendation="Sanitize and validate all user input; use parameterized MongoDB queries",
                )
        return None

    @staticmethod
    def _php_style_params(param, payload):
        from urllib.parse import quote
        parts = []
        for key, value in payload.items():
            if isinstance(value, list):
                for i, v in enumerate(value):
                    parts.append(f"{param}[{key}][{i}]={quote(str(v))}")
            else:
                parts.append(f"{param}[{key}]={quote(str(value))}")
        return "&".join(parts)

