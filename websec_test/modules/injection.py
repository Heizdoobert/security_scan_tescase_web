"""Injection testing module — SQLi, XSS, command injection."""
from collections import namedtuple
from urllib.parse import urljoin, urlencode

import requests
from websec_test.client.session import SessionClient
from websec_test.config.payloads import SQLI_PAYLOADS, XSS_PAYLOADS, CMD_INJECT_PAYLOADS, NOSQLI_PAYLOADS
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method", "param_names"])


class InjectionModule:
    """Test for SQL injection, XSS, and command injection vulnerabilities."""

    def _extract_form_inputs(self, html: str) -> list[Endpoint]:
        """Find GET forms and their input field names."""
        import re
        endpoints = []
        form_pattern = re.compile(
            r'<form[^>]*method=["\'](get|GET)["\'][^>]*>.*?</form>',
            re.DOTALL | re.IGNORECASE
        )
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            action_match = re.search(r'action=["\']([^"\']+)', form_html)
            action = action_match.group(1) if action_match else "/"
            input_names = re.findall(r'<input[^>]*name=["\']([^"\']+)[^>]*>', form_html)
            if input_names:
                endpoints.append(Endpoint(url=action, method="GET", param_names=input_names))
        return endpoints

    def _test_nosqli(self, client: SessionClient, target: str, endpoints):
        """Test for NoSQL injection via MongoDB operator payloads.

        Sends payloads in three formats (URL-encoded, JSON body, query string),
        falling through to the next format only if no bypass was found.
        """
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

                # --- URL-encoded format (PHP-style: param[$ne]=) ---
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

                # --- JSON body format (POST with Content-Type: application/json) ---
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

                # --- Query string format (raw operator as param value) ---
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

                # --- No bypass found in any format ---
                results.append(TestResult(
                    module="injection", test_name="nosql_injection",
                    status=TestStatus.PASS, severity=Severity.CRITICAL,
                    endpoint=ep.url,
                    evidence="No NoSQL injection bypass detected",
                    recommendation="No action needed",
                ))

        return results

    @staticmethod
    def _is_nosql_bypass(resp, baseline_len, baseline_text, bypass_keywords):
        """Check if response indicates a NoSQL injection bypass."""
        text_lower = resp.text.lower()
        # Check for bypass keywords regardless of length diff
        if any(kw in text_lower for kw in bypass_keywords):
            return True
        # Status 500 may indicate server processing our operator
        if resp.status_code == 500:
            return True
        # Different content length than baseline (failed auth)
        if abs(len(resp.text) - baseline_len) > 5:
            return True
        return False

    def _try_nosql_format(self, client, payloads, perform_request, baseline_len, baseline_text, bypass_keywords, format_name):
        """Try a list of NoSQL payloads in one format. Returns TestResult or None.

        perform_request(payload) must return (response, endpoint_url) or raise.
        """
        for payload in payloads:
            op_key = list(payload.keys())[0] if payload else ""
            try:
                resp, endpoint_url = perform_request(payload)
            except (requests.exceptions.ConnectionError, requests.ConnectTimeout):
                continue
            if self._is_nosql_bypass(resp, baseline_len, baseline_text, bypass_keywords):
                return TestResult(
                    module="injection", test_name="nosql_injection",
                    status=TestStatus.FAIL, severity=Severity.CRITICAL,
                    endpoint=endpoint_url,
                    evidence=f"NoSQL bypass via {format_name} operator '{op_key}': {resp.text[:150]}",
                    recommendation="Sanitize and validate all user input; use parameterized MongoDB queries",
                )
        return None

    @staticmethod
    def _php_style_params(param, payload):
        """Convert MongoDB operator payload to PHP-style query string params.

        Example:
            _php_style_params("q", {"$ne": ""}) -> "q[$ne]="
            _php_style_params("q", {"$in": ["admin"]}) -> "q[$in][0]=admin"
        """
        from urllib.parse import quote
        parts = []
        for key, value in payload.items():
            if isinstance(value, list):
                for i, v in enumerate(value):
                    parts.append(f"{param}[{key}][{i}]={quote(str(v))}")
            else:
                parts.append(f"{param}[{key}]={quote(str(value))}")
        return "&".join(parts)

    def discover(self, client: SessionClient, target: str):
        """Scan the target page for forms with input fields."""
        resp = client.get("/")
        return self._extract_form_inputs(resp.text)

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        results = []

        for ep in endpoints:
            for param in ep.param_names:
                # SQLi tests
                for payload in SQLI_PAYLOADS[:3]:
                    params = {param: payload}
                    url = f"{target.rstrip('/')}{ep.url}?{urlencode(params)}"
                    try:
                        resp = client.get(url)
                    except requests.exceptions.ConnectionError:
                        continue
                    evidence_lower = resp.text.lower()
                    if any(word in evidence_lower for word in
                           ["sql", "syntax error", "ora-", "mysql", "unclosed quotation"]):
                        results.append(TestResult(
                            module="injection",
                            test_name="sqli_detection",
                            status=TestStatus.FAIL,
                            severity=Severity.CRITICAL,
                            endpoint=url,
                            evidence=f"SQL error reflected: {resp.text[:200]}",
                            recommendation="Use parameterized queries, sanitize all inputs",
                        ))
                        break
                else:
                    results.append(TestResult(
                        module="injection",
                        test_name="sqli_detection",
                        status=TestStatus.PASS,
                        severity=Severity.CRITICAL,
                        endpoint=ep.url,
                        evidence="No SQL errors reflected for tested payloads",
                        recommendation="No action needed",
                    ))

                # XSS tests
                for payload in XSS_PAYLOADS[:3]:
                    params = {param: payload}
                    url = f"{target.rstrip('/')}{ep.url}?{urlencode(params)}"
                    try:
                        resp = client.get(url)
                    except requests.exceptions.ConnectionError:
                        continue
                    if payload in resp.text:
                        results.append(TestResult(
                            module="injection",
                            test_name="xss_detection",
                            status=TestStatus.FAIL,
                            severity=Severity.HIGH,
                            endpoint=url,
                            evidence=f"XSS payload reflected: {payload[:100]}",
                            recommendation="Encode all user-controlled data in responses",
                        ))
                        break
                else:
                    results.append(TestResult(
                        module="injection",
                        test_name="xss_detection",
                        status=TestStatus.PASS,
                        severity=Severity.HIGH,
                        endpoint=ep.url,
                        evidence="No XSS payload reflection detected",
                        recommendation="No action needed",
                    ))

                # Command injection tests
                for payload in CMD_INJECT_PAYLOADS[:2]:
                    params = {param: payload}
                    url = f"{target.rstrip('/')}{ep.url}?{urlencode(params)}"
                    try:
                        resp = client.get(url)
                    except requests.exceptions.ConnectionError:
                        continue
                    evidence_lower = resp.text.lower()
                    if any(word in evidence_lower for word in
                           ["root:", "uid=", "volume", "directory of", "bin/"]):
                        results.append(TestResult(
                            module="injection",
                            test_name="cmd_injection",
                            status=TestStatus.FAIL,
                            severity=Severity.CRITICAL,
                            endpoint=url,
                            evidence=f"Command output reflected: {resp.text[:200]}",
                            recommendation="Never pass user input to system commands",
                        ))
                        break
                else:
                    results.append(TestResult(
                        module="injection",
                        test_name="cmd_injection",
                        status=TestStatus.PASS,
                        severity=Severity.CRITICAL,
                        endpoint=ep.url,
                        evidence="No command output reflected",
                        recommendation="No action needed",
                    ))

            # NoSQL injection tests
            results.extend(self._test_nosqli(client, target, [ep]))

        return results
