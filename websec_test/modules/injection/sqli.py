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



    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Legacy test method — kept for ModuleAdapter backward compat."""
        return [r for ep in endpoints for r in [
            self.check_sqli_detection(client, target, ep),
        ]]

    def check_sqli_detection(self, client, target, endpoint):
        if not endpoint.forms and not endpoint.param_names:
            return None

        all_params = set(endpoint.param_names)
        for form in endpoint.forms:
            all_params.update(f.name for f in form.fields)

        for param in all_params:
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

