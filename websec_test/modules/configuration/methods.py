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
        """Legacy test method — kept for ModuleAdapter backward compat."""
        results = []
        for ep in endpoints:
            if ep.http_method == "OPTIONS":
                results.append(self.check_options_allow_enumeration(client, target, ep))
        for method in DANGEROUS_METHODS:
            ep = next((e for e in endpoints if e.http_method == method), None)
            if ep:
                results.append(getattr(self, f"check_{method.lower()}_method_enabled")(client, target, ep))
        results.append(self.check_verb_tampering(client, target, endpoints[0]))
        return results

    def check_options_allow_enumeration(self, client, target, endpoint):
        ep_url = getattr(endpoint, 'url', str(endpoint))
        resp = client.session.request("OPTIONS", client._resolve_url(ep_url))
        allow = resp.headers.get("Allow", "")
        if allow:
            allowed_methods = [m.strip() for m in allow.split(",")]
            dangerous_found = [m for m in allowed_methods if m.upper() in DANGEROUS_METHODS]
            if dangerous_found:
                return TestResult(module="methods", test_name="options_allow_enumeration",
                    status=TestStatus.FAIL, severity=Severity.MEDIUM, endpoint=ep_url,
                    evidence=f"OPTIONS reveals dangerous methods: {', '.join(dangerous_found)}",
                    recommendation="Restrict Allow header to only necessary methods")
            return TestResult(module="methods", test_name="options_allow_enumeration",
                status=TestStatus.PASS, severity=Severity.MEDIUM, endpoint=ep_url,
                evidence=f"OPTIONS Allow: {allow[:100]}",
                recommendation="No action needed")
        return TestResult(module="methods", test_name="options_allow_enumeration",
            status=TestStatus.PASS, severity=Severity.MEDIUM, endpoint=ep_url,
            evidence="No Allow header in OPTIONS response",
            recommendation="No action needed")

    def check_trace_method_enabled(self, client, target, endpoint):
        ep_url = getattr(endpoint, 'url', str(endpoint))
        resp = client.session.request("TRACE", client._resolve_url(ep_url))
        if resp.status_code in (200, 201, 202, 204):
            return TestResult(module="methods", test_name="trace_method_enabled",
                status=TestStatus.FAIL, severity=Severity.HIGH, endpoint=ep_url,
                evidence=f"TRACE {ep_url} returned HTTP {resp.status_code}",
                recommendation="Disable the TRACE method on production endpoints")
        return TestResult(module="methods", test_name="trace_method_enabled",
            status=TestStatus.PASS, severity=Severity.HIGH, endpoint=ep_url,
            evidence=f"TRACE {ep_url} returned HTTP {resp.status_code} (blocked)",
            recommendation="No action needed")

    def check_put_method_enabled(self, client, target, endpoint):
        ep_url = getattr(endpoint, 'url', str(endpoint))
        resp = client.session.request("PUT", client._resolve_url(ep_url))
        if resp.status_code in (200, 201, 202, 204):
            return TestResult(module="methods", test_name="put_method_enabled",
                status=TestStatus.FAIL, severity=Severity.CRITICAL, endpoint=ep_url,
                evidence=f"PUT {ep_url} returned HTTP {resp.status_code}",
                recommendation="Disable the PUT method on production endpoints")
        return TestResult(module="methods", test_name="put_method_enabled",
            status=TestStatus.PASS, severity=Severity.CRITICAL, endpoint=ep_url,
            evidence=f"PUT {ep_url} returned HTTP {resp.status_code} (blocked)",
            recommendation="No action needed")

    def check_delete_method_enabled(self, client, target, endpoint):
        ep_url = getattr(endpoint, 'url', str(endpoint))
        resp = client.session.request("DELETE", client._resolve_url(ep_url))
        if resp.status_code in (200, 201, 202, 204):
            return TestResult(module="methods", test_name="delete_method_enabled",
                status=TestStatus.FAIL, severity=Severity.CRITICAL, endpoint=ep_url,
                evidence=f"DELETE {ep_url} returned HTTP {resp.status_code}",
                recommendation="Disable the DELETE method on production endpoints")
        return TestResult(module="methods", test_name="delete_method_enabled",
            status=TestStatus.PASS, severity=Severity.CRITICAL, endpoint=ep_url,
            evidence=f"DELETE {ep_url} returned HTTP {resp.status_code} (blocked)",
            recommendation="No action needed")

    def check_verb_tampering(self, client, target, endpoint):
        resp_get = client.get("/")
        resp_post = client.post("/", data={"test": "value"})
        if resp_get.status_code != resp_post.status_code:
            resp_tamper = client.session.request("POST", client._resolve_url("/"),
                                                  data={"_method": "GET"})
            if resp_tamper.status_code == 200 and resp_tamper.status_code != resp_post.status_code:
                return TestResult(module="methods", test_name="verb_tampering",
                    status=TestStatus.FAIL, severity=Severity.HIGH, endpoint="/",
                    evidence=f"Verb tampering via _method parameter bypassed auth (HTTP {resp_tamper.status_code})",
                    recommendation="Validate HTTP method server-side, not just from headers")
            return TestResult(module="methods", test_name="verb_tampering",
                status=TestStatus.PASS, severity=Severity.HIGH, endpoint="/",
                evidence="Verb tampering blocked",
                recommendation="No action needed")
        return TestResult(module="methods", test_name="verb_tampering",
            status=TestStatus.PASS, severity=Severity.HIGH, endpoint="/",
            evidence="Verb tampering blocked (methods behave consistently)",
            recommendation="No action needed")

