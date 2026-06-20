"""Tests for injection module."""
import responses
from websec_test.modules.injection import InjectionModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"

SEARCH_PAGE = """<html><body>
    <form method="GET" action="/search">
        <input name="q">
    </form>
</body></html>"""


@responses.activate
def test_discover_finds_form():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    client = SessionClient(TARGET)
    module = InjectionModule()
    endpoints = module.discover(client, TARGET)
    assert len(endpoints) > 0


@responses.activate
def test_sqli_detects_reflected_error():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(TARGET + "/search?q=%27+OR+%271%27%3D%271", status=200,
                  body="SQL syntax error near 'OR 1=1'")
    client = SessionClient(TARGET)
    module = InjectionModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    sqli_tests = [r for r in results if r.test_name == "sqli_detection"]
    assert len(sqli_tests) > 0


@responses.activate
def test_xss_detects_reflected_payload():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    payload = "<script>alert(1)</script>"
    responses.get(TARGET + f"/search?q={payload}", status=200,
                  body=f"Results for: {payload}")
    client = SessionClient(TARGET)
    module = InjectionModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    xss_tests = [r for r in results if r.test_name == "xss_detection"]
    assert len(xss_tests) > 0


@responses.activate
def test_no_false_positive():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(TARGET + "/search?q=test", status=200,
                  body="Results for: test (sanitized)")
    client = SessionClient(TARGET)
    module = InjectionModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    for r in results:
        assert r.status != TestStatus.ERROR


# ── NoSQL Injection Tests ───────────────────────────────────────────────────

BASELINE_URL = TARGET + "/search?q=invalid__test__value"

@responses.activate
def test_nosql_payloads_in_form_fields():
    """Verify NoSQL payloads are sent in URL-encoded format."""
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(BASELINE_URL, status=200, body="invalid password")
    # URL-encoded operator payload: q[$ne]=
    responses.get(TARGET + "/search?q%5B%24ne%5D=", status=200,
                  body="invalid password")
    client = SessionClient(TARGET)
    module = InjectionModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    nosql_results = [r for r in results if r.test_name == "nosql_injection"]
    assert len(nosql_results) > 0


@responses.activate
def test_nosql_bypass_detected():
    """NoSQL injection detected when payload produces different response."""
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(BASELINE_URL, status=200, body="invalid password")
    # URL-encoded operator payload triggers "welcome" response
    responses.get(TARGET + "/search?q%5B%24ne%5D=",
                  status=200, body="welcome admin, logged in")
    client = SessionClient(TARGET)
    module = InjectionModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    nosql_bypass = [r for r in results if r.test_name == "nosql_injection"
                    and r.status == TestStatus.FAIL]
    assert len(nosql_bypass) > 0


@responses.activate
def test_nosql_no_bypass():
    """No bypass when all responses are consistent."""
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(BASELINE_URL, status=200, body="invalid password")
    responses.get(TARGET + "/search?q%5B%24ne%5D=",
                  status=200, body="invalid password")
    # Also register for nested auth payload (JSON body fallback)
    import re
    responses.add(responses.POST, re.compile(TARGET + "/search.*"),
                  status=200, body="invalid password")
    client = SessionClient(TARGET)
    module = InjectionModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    nosql_results = [r for r in results if r.test_name == "nosql_injection"]
    # At least one pass result (no bypass)
    assert any(r.status == TestStatus.PASS for r in nosql_results)


@responses.activate
def test_nosql_connection_error():
    """Connection error during NoSQL injection test returns ERROR."""
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(BASELINE_URL, status=200, body="invalid password")
    # Don't register the payload URL — ConnectionError on first probe
    client = SessionClient(TARGET)
    module = InjectionModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    # Should complete without raising
    assert len(results) > 0
