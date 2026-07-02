"""SQL injection testing module."""
from urllib.parse import urlencode

from websec_test.client.session import SessionClient
from websec_test.config.payloads import SQLI_PAYLOADS
from websec_test.modules._shared import Endpoint, parse_form_inputs
from websec_test.results.models import TestResult, TestStatus, Severity

SQL_ERROR_SIGNALS = ["sql", "syntax error", "ora-", "mysql", "unclosed quotation"]

SELECTOR_GROUPS = {"sqli_techniques": ["check_sqli_detection"]}


class SqliModule:
    """Test for SQL injection vulnerabilities."""

    def _extract_form_inputs(self, html: str) -> list[Endpoint]:
        return parse_form_inputs(html)

    def discover(self, client: SessionClient, target: str):
        resp = client.get(target.rstrip("/") + "/")
        return self._extract_form_inputs(resp.text)

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Legacy test method — kept for ModuleAdapter backward compat."""
        return [r for ep in endpoints for r in [
            self.check_sqli_detection(client, target, ep),
        ]]

    def check_sqli_detection(self, client, target, endpoint):
        for param in endpoint.param_names:
            for payload in SQLI_PAYLOADS[:3]:
                params = {param: payload}
                url = f"{target.rstrip('/')}{endpoint.url}?{urlencode(params)}"
                try:
                    resp = client.get(url)
                except:
                    continue
                if any(word in resp.text.lower() for word in SQL_ERROR_SIGNALS):
                    return TestResult(
                        module="sqli", test_name="sqli_detection",
                        status=TestStatus.FAIL, severity=Severity.CRITICAL,
                        endpoint=url,
                        evidence=f"SQL error reflected: {resp.text[:200]}",
                        recommendation="Use parameterized queries, sanitize all inputs",
                    )
        return TestResult(
            module="sqli", test_name="sqli_detection",
            status=TestStatus.PASS, severity=Severity.CRITICAL,
            endpoint=endpoint.url,
            evidence="No SQL errors reflected for tested payloads",
            recommendation="No action needed",
        )

