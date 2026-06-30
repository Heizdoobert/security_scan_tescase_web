"""XSS (Cross-Site Scripting) testing module."""
from urllib.parse import urlencode

from websec_test.client.session import SessionClient
from websec_test.config.payloads import XSS_PAYLOADS
from websec_test.engine.builder import CheckSpec
from websec_test.engine.registry import register
from websec_test.modules._shared import Endpoint, parse_form_inputs
from websec_test.results.models import TestResult, TestStatus, Severity


class XssModule:
    """Test for reflected XSS vulnerabilities."""

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
                for payload in XSS_PAYLOADS[:3]:
                    params = {param: payload}
                    url = f"{target.rstrip('/')}{ep.url}?{urlencode(params)}"
                    try:
                        resp = client.get(url)
                    except:
                        continue
                    if payload in resp.text:
                        results.append(TestResult(
                            module="xss", test_name="xss_detection",
                            status=TestStatus.FAIL, severity=Severity.HIGH,
                            endpoint=url,
                            evidence=f"XSS payload reflected: {payload[:100]}",
                            recommendation="Encode all user-controlled data in responses",
                        ))
                        break
                else:
                    results.append(TestResult(
                        module="xss", test_name="xss_detection",
                        status=TestStatus.PASS, severity=Severity.HIGH,
                        endpoint=ep.url,
                        evidence="No XSS payload reflection detected",
                        recommendation="No action needed",
                    ))
        return results


def _extract_form_inputs(html: str, target: str):
    from urllib.parse import urljoin
    endpoints = parse_form_inputs(html)
    for ep in endpoints:
        ep["url"] = urljoin(target + "/", ep["url"].lstrip("/"))
    return endpoints


def _check_xss_fn(client, target, blackboard):
    resp = client.get("/")
    forms = _extract_form_inputs(resp.text, target)
    if not forms:
        return TestResult(
            module="xss", test_name="xss_detection",
            status=TestStatus.PASS, severity=Severity.HIGH,
            endpoint="/", evidence="No forms with inputs found",
            recommendation="No action needed",
        )
    for form in forms:
        for param in form["param_names"]:
            for payload in XSS_PAYLOADS[:3]:
                url = f"{form['url']}?{urlencode({param: payload})}"
                try:
                    r = client.get(url)
                except:
                    continue
                if payload in r.text:
                    return TestResult(
                        module="xss", test_name="xss_detection",
                        status=TestStatus.FAIL, severity=Severity.HIGH,
                        endpoint=url,
                        evidence=f"XSS payload reflected: {payload[:100]}",
                        recommendation="Encode all user-controlled data in responses",
                    )
    return TestResult(
        module="xss", test_name="xss_detection",
        status=TestStatus.PASS, severity=Severity.HIGH,
        endpoint="/", evidence="No XSS payload reflection detected",
        recommendation="No action needed",
    )


@register("xss")
def xss_check_specs():
    return [
        CheckSpec("xss_detection", _check_xss_fn,
                  severity=Severity.HIGH, module_name="xss"),
    ]
