"""HTTP methods security test module.

Checks for dangerous HTTP methods: OPTIONS enumeration, TRACE, PUT, DELETE,
and verb tampering vulnerabilities.
"""
from collections import namedtuple

from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method", "http_method"])

DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE", "CONNECT"]


class MethodsModule:
    """Test for HTTP method vulnerabilities: verb tampering, dangerous methods."""

    def discover(self, client: SessionClient, target: str):
        """Return endpoints to test with various HTTP methods."""
        return [
            Endpoint(url="/", method="OPTIONS", http_method="OPTIONS"),
            Endpoint(url="/admin", method="TRACE", http_method="TRACE"),
            Endpoint(url="/", method="PUT", http_method="PUT"),
            Endpoint(url="/", method="DELETE", http_method="DELETE"),
        ]

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Probe each endpoint with uncommon HTTP methods."""
        results = []

        # OPTIONS method enumeration
        ep_options = [ep for ep in endpoints if ep.http_method == "OPTIONS"]
        for ep in ep_options:
            resp = client.session.request("OPTIONS", client._resolve_url(ep.url))
            allow = resp.headers.get("Allow", "")
            if allow:
                allowed_methods = [m.strip() for m in allow.split(",")]
                dangerous_found = [m for m in allowed_methods if m.upper() in DANGEROUS_METHODS]
                if dangerous_found:
                    results.append(TestResult(
                        module="methods", test_name="options_allow_enumeration",
                        status=TestStatus.FAIL, severity=Severity.MEDIUM,
                        endpoint=ep.url,
                        evidence=f"OPTIONS reveals dangerous methods: {', '.join(dangerous_found)}",
                        recommendation="Restrict Allow header to only necessary methods",
                    ))
                else:
                    results.append(TestResult(
                        module="methods", test_name="options_allow_enumeration",
                        status=TestStatus.PASS, severity=Severity.MEDIUM,
                        endpoint=ep.url,
                        evidence=f"OPTIONS Allow: {allow[:100]}",
                        recommendation="No action needed",
                    ))
            else:
                results.append(TestResult(
                    module="methods", test_name="options_allow_enumeration",
                    status=TestStatus.PASS, severity=Severity.MEDIUM,
                    endpoint=ep.url,
                    evidence="No Allow header in OPTIONS response",
                    recommendation="No action needed",
                ))

        # Dangerous method checks (TRACE, PUT, DELETE)
        for method in DANGEROUS_METHODS:
            ep = next((e for e in endpoints if e.http_method == method), None)
            if not ep:
                continue
            resp = client.session.request(method, client._resolve_url(ep.url))
            if resp.status_code in (200, 201, 202, 204):
                results.append(TestResult(
                    module="methods", test_name=f"{method.lower()}_method_enabled",
                    status=TestStatus.FAIL,
                    severity=Severity.CRITICAL if method in ("PUT", "DELETE") else Severity.HIGH,
                    endpoint=ep.url,
                    evidence=f"{method} {ep.url} returned HTTP {resp.status_code}",
                    recommendation=f"Disable the {method} method on production endpoints",
                ))
            else:
                results.append(TestResult(
                    module="methods", test_name=f"{method.lower()}_method_enabled",
                    status=TestStatus.PASS,
                    severity=Severity.CRITICAL if method in ("PUT", "DELETE") else Severity.HIGH,
                    endpoint=ep.url,
                    evidence=f"{method} {ep.url} returned HTTP {resp.status_code} (blocked)",
                    recommendation="No action needed",
                ))

        # Verb tampering: try GET with POST-only endpoint body
        resp_get = client.get("/")
        resp_post = client.post("/", data={"test": "value"})
        if resp_get.status_code != resp_post.status_code:
            # Different methods behave differently — try to exploit
            resp_tamper = client.session.request("POST", client._resolve_url("/"),
                                                  data={"_method": "GET"})
            if resp_tamper.status_code == 200 and resp_tamper.status_code != resp_post.status_code:
                results.append(TestResult(
                    module="methods", test_name="verb_tampering",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint="/",
                    evidence=f"Verb tampering via _method parameter bypassed auth (HTTP {resp_tamper.status_code})",
                    recommendation="Validate HTTP method server-side, not just from headers",
                ))
            else:
                results.append(TestResult(
                    module="methods", test_name="verb_tampering",
                    status=TestStatus.PASS, severity=Severity.HIGH,
                    endpoint="/",
                    evidence="Verb tampering blocked",
                    recommendation="No action needed",
                ))
        else:
            results.append(TestResult(
                module="methods", test_name="verb_tampering",
                status=TestStatus.PASS, severity=Severity.HIGH,
                endpoint="/",
                evidence="Verb tampering blocked (methods behave consistently)",
                recommendation="No action needed",
            ))

        return results
