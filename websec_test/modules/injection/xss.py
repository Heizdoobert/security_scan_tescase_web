"""XSS (Cross-Site Scripting) testing module."""
from urllib.parse import urlencode

from websec_test.client.session import SessionClient
from websec_test.config.payloads import XSS_PAYLOADS
from websec_test.modules._shared import Endpoint, parse_form_inputs
from websec_test.results.models import TestResult, TestStatus, Severity


class XssModule:
    """Test for reflected XSS vulnerabilities."""



    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Legacy test method — kept for ModuleAdapter backward compat."""
        return [r for ep in endpoints for r in [
            self.check_xss_detection(client, target, ep),
        ]]

    def check_xss_detection(self, client, target, endpoint):
        if not endpoint.forms and not endpoint.param_names:
            return None

        all_params = set(endpoint.param_names)
        for form in endpoint.forms:
            all_params.update(f.name for f in form.fields)

        for param in all_params:
            for payload in XSS_PAYLOADS[:3]:
                params = {param: payload}
                url = f"{target.rstrip('/')}{endpoint.url}?{urlencode(params)}"
                try:
                    resp = client.get(url)
                except:
                    continue
                if payload in resp.text:
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
            endpoint=endpoint.url,
            evidence="No XSS payload reflection detected",
            recommendation="No action needed",
        )

