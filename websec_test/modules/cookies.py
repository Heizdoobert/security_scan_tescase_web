"""Cookie security test module.

Checks Set-Cookie response headers for missing security flags:
Secure, HttpOnly, SameSite, and expiry attributes.
"""
from collections import namedtuple

import requests
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


# ── Check-level BT support ──────────────────────────────────────────────

from websec_test.engine.registry import register
from websec_test.engine.builder import CheckSpec


def _parse_cookies_from_setcookie_headers(resp) -> list[dict]:
    """Extract cookie attributes from Set-Cookie response headers."""
    cookies = []
    raw_headers = []
    if hasattr(resp, "raw") and resp.raw is not None:
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
        cookies.append(cookie)
    return cookies


def _check_cookie_flag(client, target, blackboard, flag_name, test_name, severity, fail_fmt, fail_rec):
    """Generic check for a cookie security flag. Reads endpoints from blackboard."""
    endpoints = blackboard.get("cookies_discover_endpoints", None)
    if not endpoints:
        return TestResult(
            module="cookies", test_name=test_name,
            status=TestStatus.ERROR, severity=severity,
            endpoint=target, evidence="No endpoints discovered",
            recommendation=fail_rec,
        )
    ep = endpoints[0]
    try:
        resp = client.get(ep.url)
    except requests.exceptions.RequestException as e:
        return TestResult(
            module="cookies", test_name=test_name,
            status=TestStatus.ERROR, severity=severity,
            endpoint=ep.url, evidence=f"Request failed: {e}",
            recommendation=fail_rec,
        )
    cookies = _parse_cookies_from_setcookie_headers(resp)
    if not cookies:
        return TestResult(
            module="cookies", test_name=test_name,
            status=TestStatus.PASS, severity=severity,
            endpoint=ep.url, evidence="No cookies set",
            recommendation="No action needed",
        )
    bad = [c["name"] for c in cookies if not c[flag_name]]
    if bad:
        return TestResult(
            module="cookies", test_name=test_name,
            status=TestStatus.FAIL, severity=severity,
            endpoint=ep.url,
            evidence=fail_fmt.format(cookies=", ".join(bad)),
            recommendation=fail_rec,
        )
    return TestResult(
        module="cookies", test_name=test_name,
        status=TestStatus.PASS, severity=severity,
        endpoint=ep.url, evidence=f"All cookies have {flag_name} flag",
        recommendation="No action needed",
    )


@register("cookies")
def cookies_check_specs():
    from functools import partial
    return [
        CheckSpec("missing_secure_flag",
                  partial(_check_cookie_flag, flag_name="secure", test_name="missing_secure_flag",
                          severity=Severity.HIGH,
                          fail_fmt="Cookies missing Secure flag: {cookies}",
                          fail_rec="Set Secure flag on all cookies"),
                  severity=Severity.HIGH, module_name="cookies"),
        CheckSpec("missing_httponly_flag",
                  partial(_check_cookie_flag, flag_name="httponly", test_name="missing_httponly_flag",
                          severity=Severity.MEDIUM,
                          fail_fmt="Cookies missing HttpOnly flag: {cookies}",
                          fail_rec="Set HttpOnly flag on cookies not needed by JavaScript"),
                  severity=Severity.MEDIUM, module_name="cookies"),
        CheckSpec("missing_samesite_flag",
                  partial(_check_cookie_flag, flag_name="samesite", test_name="missing_samesite_flag",
                          severity=Severity.MEDIUM,
                          fail_fmt="Cookies missing SameSite flag: {cookies}",
                          fail_rec="Set SameSite=Lax or SameSite=Strict on all cookies"),
                  severity=Severity.MEDIUM, module_name="cookies"),
    ]
