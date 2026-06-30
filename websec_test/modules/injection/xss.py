"""XSS (Cross-Site Scripting) testing module."""
from urllib.parse import urlencode

from websec_test.client.session import SessionClient
from websec_test.config.payloads import XSS_PAYLOADS
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

