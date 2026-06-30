"""Command injection testing module."""
from urllib.parse import urlencode

from websec_test.client.session import SessionClient
from websec_test.config.payloads import CMD_INJECT_PAYLOADS
from websec_test.modules._shared import Endpoint, parse_form_inputs
from websec_test.results.models import TestResult, TestStatus, Severity

CMD_OUTPUT_SIGNALS = ["root:", "uid=", "volume", "directory of", "bin/"]


class CmdInjectionModule:
    """Test for command injection vulnerabilities."""

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
                for payload in CMD_INJECT_PAYLOADS[:2]:
                    params = {param: payload}
                    url = f"{target.rstrip('/')}{ep.url}?{urlencode(params)}"
                    try:
                        resp = client.get(url)
                    except:
                        continue
                    if any(word in resp.text.lower() for word in CMD_OUTPUT_SIGNALS):
                        results.append(TestResult(
                            module="cmd_injection", test_name="cmd_injection",
                            status=TestStatus.FAIL, severity=Severity.CRITICAL,
                            endpoint=url,
                            evidence=f"Command output reflected: {resp.text[:200]}",
                            recommendation="Never pass user input to system commands",
                        ))
                        break
                else:
                    results.append(TestResult(
                        module="cmd_injection", test_name="cmd_injection",
                        status=TestStatus.PASS, severity=Severity.CRITICAL,
                        endpoint=ep.url,
                        evidence="No command output reflected",
                        recommendation="No action needed",
                    ))
        return results

