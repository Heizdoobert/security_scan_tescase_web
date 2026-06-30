"""SQL injection testing module."""
from urllib.parse import urlencode

from websec_test.client.session import SessionClient
from websec_test.config.payloads import SQLI_PAYLOADS
from websec_test.engine.builder import CheckSpec
from websec_test.engine.registry import register
from websec_test.modules._shared import Endpoint, parse_form_inputs
from websec_test.results.models import TestResult, TestStatus, Severity

SQL_ERROR_SIGNALS = ["sql", "syntax error", "ora-", "mysql", "unclosed quotation"]


class SqliModule:
    """Test for SQL injection vulnerabilities."""

    def _extract_form_inputs(self, html: str) -> list[Endpoint]:
        return [Endpoint(url=ep["url"], method="GET", param_names=ep["param_names"])
                for ep in parse_form_inputs(html)]

    def discover(self, client: SessionClient, target: str):
        resp = client.get(target.rstrip("/") + "/")
        return self._extract_form_inputs(resp.text)

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        results = []
        for ep in endpoints:
            for param in ep.param_names:
                for payload in SQLI_PAYLOADS[:3]:
                    params = {param: payload}
                    url = f"{target.rstrip('/')}{ep.url}?{urlencode(params)}"
                    try:
                        resp = client.get(url)
                    except:
                        continue
                    if any(word in resp.text.lower() for word in SQL_ERROR_SIGNALS):
                        results.append(TestResult(
                            module="sqli", test_name="sqli_detection",
                            status=TestStatus.FAIL, severity=Severity.CRITICAL,
                            endpoint=url,
                            evidence=f"SQL error reflected: {resp.text[:200]}",
                            recommendation="Use parameterized queries, sanitize all inputs",
                        ))
                        break
                else:
                    results.append(TestResult(
                        module="sqli", test_name="sqli_detection",
                        status=TestStatus.PASS, severity=Severity.CRITICAL,
                        endpoint=ep.url,
                        evidence="No SQL errors reflected for tested payloads",
                        recommendation="No action needed",
                    ))
        return results


def _extract_form_inputs(html: str, target: str):
    from urllib.parse import urljoin
    endpoints = parse_form_inputs(html)
    for ep in endpoints:
        ep["url"] = urljoin(target + "/", ep["url"].lstrip("/"))
    return endpoints


def _check_sqli_fn(client, target, blackboard):
    from urllib.parse import urlencode
    resp = client.get("/")
    forms = _extract_form_inputs(resp.text, target)
    if not forms:
        return TestResult(
            module="sqli", test_name="sqli_detection",
            status=TestStatus.PASS, severity=Severity.CRITICAL,
            endpoint="/", evidence="No forms with inputs found",
            recommendation="No action needed",
        )
    for form in forms:
        for param in form["param_names"]:
            for payload in SQLI_PAYLOADS[:3]:
                url = f"{form['url']}?{urlencode({param: payload})}"
                try:
                    r = client.get(url)
                except:
                    continue
                if any(word in r.text.lower() for word in SQL_ERROR_SIGNALS):
                    return TestResult(
                        module="sqli", test_name="sqli_detection",
                        status=TestStatus.FAIL, severity=Severity.CRITICAL,
                        endpoint=url,
                        evidence=f"SQL error reflected: {r.text[:200]}",
                        recommendation="Use parameterized queries, sanitize all inputs",
                    )
    return TestResult(
        module="sqli", test_name="sqli_detection",
        status=TestStatus.PASS, severity=Severity.CRITICAL,
        endpoint="/", evidence="No SQL errors reflected for tested payloads",
        recommendation="No action needed",
    )


@register("sqli")
def sqli_check_specs():
    return [
        CheckSpec("sqli_detection", _check_sqli_fn,
                  severity=Severity.CRITICAL, module_name="sqli"),
    ]
