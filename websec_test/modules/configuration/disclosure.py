"""Information disclosure test module.

Checks for information leaks: server version banners, X-Powered-By headers,
directory listing, and stack traces on error pages.
"""
from collections import namedtuple

import requests
from websec_test.client.session import SessionClient
from websec_test.config.payloads import COMMON_PATHS
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])

# Sensitive headers that can leak technology stack information
SENSITIVE_HEADERS = [
    ("Server", "Server header reveals server software version", Severity.MEDIUM),
    ("X-Powered-By", "X-Powered-By header reveals technology stack", Severity.LOW),
    ("X-AspNet-Version", "X-AspNet-Version leaks ASP.NET version", Severity.LOW),
    ("X-AspNetMvc-Version", "X-AspNetMvc-Version leaks MVC version", Severity.LOW),
]

# Patterns that suggest directory listing is enabled
DIRECTORY_LISTING_SIGNATURES = [
    "index of", "directory listing", "<title>index of", "parent directory",
    "name</a>", "last modified", "folder",
]


class DisclosureModule:
    """Test for information disclosure vulnerabilities."""

    def discover(self, client: SessionClient, target: str):
        """Return the root endpoint and common directories to test."""
        endpoints = [Endpoint(url="/", method="GET")]
        # Add common directories that might have listing enabled
        for path in COMMON_PATHS[:6]:
            endpoints.append(Endpoint(url=path, method="GET"))
        return endpoints

    def _check_info_headers(self, resp) -> list[TestResult]:
        """Check response headers for version/banner leaks."""
        results = []
        for header, evidence, severity in SENSITIVE_HEADERS:
            value = resp.headers.get(header, "")
            if value:
                results.append(TestResult(
                    module="disclosure", test_name=f"info_header_{header.lower().replace('-', '_')}",
                    status=TestStatus.FAIL, severity=severity,
                    endpoint="/",
                    evidence=f"{evidence}: {value[:100]}",
                    recommendation=f"Remove or obfuscate the {header} header",
                ))
            else:
                results.append(TestResult(
                    module="disclosure", test_name=f"info_header_{header.lower().replace('-', '_')}",
                    status=TestStatus.PASS, severity=severity,
                    endpoint="/",
                    evidence=f"No {header} header present",
                    recommendation="No action needed",
                ))
        return results

    def _check_directory_listing(self, resp, url: str) -> TestResult:
        """Check if the response suggests directory listing is enabled."""
        text_lower = resp.text.lower()
        for signature in DIRECTORY_LISTING_SIGNATURES:
            if signature in text_lower:
                return TestResult(
                    module="disclosure", test_name="directory_listing",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=url,
                    evidence=f"Response contains directory listing signature: '{signature}'",
                    recommendation="Disable directory listing on the web server",
                )
        return TestResult(
            module="disclosure", test_name="directory_listing",
            status=TestStatus.PASS, severity=Severity.HIGH,
            endpoint=url,
            evidence="No directory listing detected",
            recommendation="No action needed",
        )

    def _check_stack_trace(self, client: SessionClient) -> TestResult:
        """Trigger a 404 error and check for stack traces."""
        resp = client.get("/nonexistent_page_xyz_123_test")
        stack_indicators = [
            "stack trace", "stacktrace", "at ", "in <module>",
            "file \"", "line ", "traceback", "exception",
            "System.Exception", "java.lang", "NullPointerReference",
        ]
        text_lower = resp.text.lower()
        if resp.status_code == 500 or any(indicator in text_lower for indicator in stack_indicators):
            return TestResult(
                module="disclosure", test_name="stack_trace_error",
                status=TestStatus.FAIL, severity=Severity.HIGH,
                endpoint="/nonexistent_page_xyz_123_test",
                evidence=f"HTTP {resp.status_code} with possible stack trace content",
                recommendation="Configure custom error pages, disable debug mode",
            )
        return TestResult(
            module="disclosure", test_name="stack_trace_error",
            status=TestStatus.PASS, severity=Severity.HIGH,
            endpoint="/nonexistent_page_xyz_123_test",
            evidence=f"HTTP {resp.status_code} with clean error page",
            recommendation="No action needed",
        )

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Legacy test method — kept for ModuleAdapter backward compat."""
        results = []
        for ep in endpoints:
            try:
                resp = client.get(ep.url)
                if ep.url == "/":
                    for header, evidence, severity in SENSITIVE_HEADERS:
                        n = f"info_header_{header.lower().replace('-', '_')}"
                        results.append(getattr(self, f"check_{n}")(client, target, ep))
                if ep.url != "/" and resp.status_code == 200:
                    results.append(self.check_directory_listing(client, target, ep))
            except Exception:
                continue
        results.append(self.check_stack_trace_error(client, target, endpoints[0]))
        return results

    def check_info_header_server(self, client, target, endpoint):
        e = getattr(endpoint, 'url', str(endpoint))
        resp = client.get(e)
        value = resp.headers.get("Server", "")
        if value:
            return TestResult(module="disclosure", test_name="info_header_server",
                status=TestStatus.FAIL, severity=Severity.MEDIUM, endpoint="/",
                evidence=f"Server header reveals server software version: {value[:100]}",
                recommendation="Remove or obfuscate the Server header")
        return TestResult(module="disclosure", test_name="info_header_server",
            status=TestStatus.PASS, severity=Severity.MEDIUM, endpoint="/",
            evidence="No Server header present", recommendation="No action needed")

    def check_info_header_x_powered_by(self, client, target, endpoint):
        e = getattr(endpoint, 'url', str(endpoint))
        resp = client.get(e)
        value = resp.headers.get("X-Powered-By", "")
        if value:
            return TestResult(module="disclosure", test_name="info_header_x_powered_by",
                status=TestStatus.FAIL, severity=Severity.LOW, endpoint="/",
                evidence=f"X-Powered-By header reveals technology stack: {value[:100]}",
                recommendation="Remove or obfuscate the X-Powered-By header")
        return TestResult(module="disclosure", test_name="info_header_x_powered_by",
            status=TestStatus.PASS, severity=Severity.LOW, endpoint="/",
            evidence="No X-Powered-By header present", recommendation="No action needed")

    def check_info_header_x_aspnet_version(self, client, target, endpoint):
        e = getattr(endpoint, 'url', str(endpoint))
        resp = client.get(e)
        value = resp.headers.get("X-AspNet-Version", "")
        if value:
            return TestResult(module="disclosure", test_name="info_header_x_aspnet_version",
                status=TestStatus.FAIL, severity=Severity.LOW, endpoint="/",
                evidence=f"X-AspNet-Version leaks ASP.NET version: {value[:100]}",
                recommendation="Remove or obfuscate the X-AspNet-Version header")
        return TestResult(module="disclosure", test_name="info_header_x_aspnet_version",
            status=TestStatus.PASS, severity=Severity.LOW, endpoint="/",
            evidence="No X-AspNet-Version header present", recommendation="No action needed")

    def check_info_header_x_aspnetmvc_version(self, client, target, endpoint):
        e = getattr(endpoint, 'url', str(endpoint))
        resp = client.get(e)
        value = resp.headers.get("X-AspNetMvc-Version", "")
        if value:
            return TestResult(module="disclosure", test_name="info_header_x_aspnetmvc_version",
                status=TestStatus.FAIL, severity=Severity.LOW, endpoint="/",
                evidence=f"X-AspNetMvc-Version leaks MVC version: {value[:100]}",
                recommendation="Remove or obfuscate the X-AspNetMvc-Version header")
        return TestResult(module="disclosure", test_name="info_header_x_aspnetmvc_version",
            status=TestStatus.PASS, severity=Severity.LOW, endpoint="/",
            evidence="No X-AspNetMvc-Version header present", recommendation="No action needed")

    def check_directory_listing(self, client, target, endpoint):
        return self._check_directory_listing(client.get(getattr(endpoint, 'url', str(endpoint))),
                                              getattr(endpoint, 'url', str(endpoint)))

    def check_stack_trace_error(self, client, target, endpoint):
        return self._check_stack_trace(client)

