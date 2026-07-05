"""Tests for cookie security module."""
import responses
from websec_test.modules.configuration.cookies import CookiesModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"


@responses.activate
def test_no_cookies_pass():
    """No cookies set should result in all passes."""
    responses.get(TARGET + "/", status=200, body="ok")
    client = SessionClient(TARGET)
    module = CookiesModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    assert len(results) == 3
    for r in results:
        assert r.status == TestStatus.PASS


@responses.activate
def test_secure_cookie_pass():
    """Cookie with all security flags should pass."""
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax"})
    client = SessionClient(TARGET)
    module = CookiesModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    for r in results:
        assert r.status == TestStatus.PASS, f"{r.test_name} should PASS"


@responses.activate
def test_insecure_cookie_fail():
    """Cookie without any flags should fail all three checks."""
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={"Set-Cookie": "session=abc123"})
    client = SessionClient(TARGET)
    module = CookiesModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    fail_results = [r for r in results if r.status == TestStatus.FAIL]
    assert len(fail_results) == 3
    names = [r.test_name for r in fail_results]
    assert "missing_secure_flag" in names
    assert "missing_httponly_flag" in names
    assert "missing_samesite_flag" in names


@responses.activate
def test_multiple_cookies_mixed():
    """Multiple cookies where some have Secure and others don't."""
    responses.get(
        TARGET + "/", status=200, body="ok",
        headers=[("Set-Cookie", "session=abc123; Secure; HttpOnly"),
                 ("Set-Cookie", "tracking=xyz; Path=/")]
    )
    client = SessionClient(TARGET)
    module = CookiesModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    # tracking=xyz is missing all flags, session=abc123 has Secure+HttpOnly
    secure_fails = [r for r in results if r.test_name == "missing_secure_flag" and r.status == TestStatus.FAIL]
    httponly_fails = [r for r in results if r.test_name == "missing_httponly_flag" and r.status == TestStatus.FAIL]
    samesite_fails = [r for r in results if r.test_name == "missing_samesite_flag" and r.status == TestStatus.FAIL]
    assert len(secure_fails) == 1  # tracking missing Secure
    assert len(httponly_fails) == 1  # tracking missing HttpOnly
    assert len(samesite_fails) == 1  # both missing SameSite


@responses.activate
def test_discover_returns_root():
    """Discover should return a single root endpoint."""
    responses.get(TARGET + "/", status=200, body="ok")
    client = SessionClient(TARGET)
    module = CookiesModule()
    endpoints = module.discover(client, TARGET)
    assert len(endpoints) == 1
    assert endpoints[0].url == "/"
