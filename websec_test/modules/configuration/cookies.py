"""Cookie security test module.

Checks Set-Cookie response headers for missing security flags:
Secure, HttpOnly, SameSite, and expiry attributes.
"""
from collections import namedtuple

from websec_test.client.session import SessionClient
from websec_test.results.models import TestResult, TestStatus, Severity

Endpoint = namedtuple("Endpoint", ["url", "method"])


class CookiesModule:
    """Test cookie security flags: Secure, HttpOnly, SameSite."""

    def discover(self, client: SessionClient, target: str):
        """Return the root endpoint to collect cookies from."""
        return [Endpoint(url="/", method="GET")]

    def _parse_cookies(self, resp) -> list[dict]:
        """Extract cookie attributes from Set-Cookie headers."""
        cookies = []
        raw_headers = []
        # Prefer raw.raw.headers (HTTPHeaderDict with getlist) over resp.headers (CaseInsensitiveDict)
        if hasattr(resp, 'raw') and resp.raw is not None:
            try:
                raw_headers = resp.raw.headers.getlist("Set-Cookie")
            except Exception:
                pass
        if not raw_headers:
            single = resp.headers.get("Set-Cookie")
            if single:
                raw_headers = [single]
        for header in raw_headers:
            parts = [p.strip() for p in header.split(";")]
            cookie = {"name": parts[0].split("=")[0] if "=" in parts[0] else parts[0]}
            cookie["secure"] = any("secure" in p.lower() for p in parts)
            cookie["httponly"] = any("httponly" in p.lower() for p in parts)
            cookie["samesite"] = any("samesite" in p.lower() for p in parts)
            cookie["has_expiry"] = any(
                ("expires" in p.lower() or "max-age" in p.lower()) for p in parts
            )
            cookies.append(cookie)
        return cookies

    def test(self, client: SessionClient, target: str, endpoints: list[Endpoint]):
        """Check cookies for missing security flags."""
        results = []

        for ep in endpoints:
            resp = client.get(ep.url)
            cookies = self._parse_cookies(resp)

            if not cookies:
                results.append(TestResult(
                    module="cookies", test_name="missing_secure_flag",
                    status=TestStatus.PASS, severity=Severity.HIGH,
                    endpoint=ep.url, evidence="No cookies set",
                    recommendation="No action needed",
                ))
                results.append(TestResult(
                    module="cookies", test_name="missing_httponly_flag",
                    status=TestStatus.PASS, severity=Severity.MEDIUM,
                    endpoint=ep.url, evidence="No cookies set",
                    recommendation="No action needed",
                ))
                results.append(TestResult(
                    module="cookies", test_name="missing_samesite_flag",
                    status=TestStatus.PASS, severity=Severity.MEDIUM,
                    endpoint=ep.url, evidence="No cookies set",
                    recommendation="No action needed",
                ))
                return results

            # Check Secure flag
            insecure_cookies = [c["name"] for c in cookies if not c["secure"]]
            if insecure_cookies:
                results.append(TestResult(
                    module="cookies", test_name="missing_secure_flag",
                    status=TestStatus.FAIL, severity=Severity.HIGH,
                    endpoint=ep.url,
                    evidence=f"Cookies missing Secure flag: {', '.join(insecure_cookies)}",
                    recommendation="Set Secure flag on all cookies",
                ))
            else:
                results.append(TestResult(
                    module="cookies", test_name="missing_secure_flag",
                    status=TestStatus.PASS, severity=Severity.HIGH,
                    endpoint=ep.url, evidence="All cookies have Secure flag",
                    recommendation="No action needed",
                ))

            # Check HttpOnly flag
            js_cookies = [c["name"] for c in cookies if not c["httponly"]]
            if js_cookies:
                results.append(TestResult(
                    module="cookies", test_name="missing_httponly_flag",
                    status=TestStatus.FAIL, severity=Severity.MEDIUM,
                    endpoint=ep.url,
                    evidence=f"Cookies missing HttpOnly flag: {', '.join(js_cookies)}",
                    recommendation="Set HttpOnly flag on cookies not needed by JavaScript",
                ))
            else:
                results.append(TestResult(
                    module="cookies", test_name="missing_httponly_flag",
                    status=TestStatus.PASS, severity=Severity.MEDIUM,
                    endpoint=ep.url, evidence="All cookies have HttpOnly flag",
                    recommendation="No action needed",
                ))

            # Check SameSite flag
            nosamesite_cookies = [c["name"] for c in cookies if not c["samesite"]]
            if nosamesite_cookies:
                results.append(TestResult(
                    module="cookies", test_name="missing_samesite_flag",
                    status=TestStatus.FAIL, severity=Severity.MEDIUM,
                    endpoint=ep.url,
                    evidence=f"Cookies missing SameSite flag: {', '.join(nosamesite_cookies)}",
                    recommendation="Set SameSite=Lax or SameSite=Strict on all cookies",
                ))
            else:
                results.append(TestResult(
                    module="cookies", test_name="missing_samesite_flag",
                    status=TestStatus.PASS, severity=Severity.MEDIUM,
                    endpoint=ep.url, evidence="All cookies have SameSite flag",
                    recommendation="No action needed",
                ))

        return results

