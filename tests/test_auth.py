"""Tests for auth module."""
import responses
from websec_test.modules.auth import AuthModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s"

LOGIN_PAGE = """<html><body>
    <form method="POST" action="/login">
        <input name="username"><input name="password">
    </form>
</body></html>"""


@responses.activate
def test_discover_finds_login_form():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    client = SessionClient(TARGET)
    module = AuthModule(credentials="admin:admin")
    endpoints = module.discover(client, TARGET)
    urls = [e.url for e in endpoints]
    assert "/login" in urls


@responses.activate
def test_blank_password_login():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    # 2 SQLi + 10 rate limiting + 2 username enumeration = 14 POSTs
    for _ in range(14):
        responses.post(TARGET + "/login", status=200, body="Invalid")
    client = SessionClient(TARGET)
    module = AuthModule(credentials="admin:admin123")
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    login_tests = [r for r in results if r.test_name == "blank_password_login"]
    assert len(login_tests) > 0


@responses.activate
def test_sqli_login_bypass():
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    # First SQLi POST succeeds with bypass
    responses.post(TARGET + "/login", status=200, body="Welcome admin")
    responses.post(TARGET + "/login", status=200, body="Invalid")
    # 10 rate limiting + 2 username enumeration = 12 POSTs
    for _ in range(12):
        responses.post(TARGET + "/login", status=200, body="Invalid")
    client = SessionClient(TARGET)
    module = AuthModule(credentials="admin:admin")
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    bypass_tests = [r for r in results if r.test_name == "sqli_login_bypass"]
    assert len(bypass_tests) > 0
    assert bypass_tests[0].status == TestStatus.FAIL


@responses.activate
def test_rate_limiting_detected():
    """Rate limiting should pass when server returns 429."""
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    # 2 SQLi POSTs + 9 non-429 + 1 429 = 12 POSTs
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="Invalid")
    for _ in range(9):
        responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=429, body="Too Many Requests")
    # 2 username enumeration POSTs
    responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="Invalid")
    client = SessionClient(TARGET)
    module = AuthModule(credentials="admin:admin")
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    rate_results = [r for r in results if r.test_name == "rate_limiting"]
    assert len(rate_results) == 1
    assert rate_results[0].status == TestStatus.PASS


@responses.activate
def test_rate_limiting_not_detected():
    """No 429 response should make rate limiting fail."""
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    # 14 POSTs total: 2 SQLi + 10 rate + 2 enum
    for _ in range(14):
        responses.post(TARGET + "/login", status=200, body="Invalid")
    client = SessionClient(TARGET)
    module = AuthModule(credentials="admin:admin")
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    rate_results = [r for r in results if r.test_name == "rate_limiting"]
    assert len(rate_results) == 1
    assert rate_results[0].status == TestStatus.FAIL


@responses.activate
def test_username_enumeration_detected():
    """Different responses for valid vs invalid username should fail."""
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.post(TARGET + "/login", status=200, body="Invalid password")
    responses.post(TARGET + "/login", status=200, body="Invalid password")
    for _ in range(10):
        responses.post(TARGET + "/login", status=200, body="Invalid")
    responses.post(TARGET + "/login", status=200, body="Invalid password")
    responses.post(TARGET + "/login", status=200, body="User not found")
    client = SessionClient(TARGET)
    module = AuthModule(credentials="admin:admin")
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    enum_results = [r for r in results if r.test_name == "username_enumeration"]
    assert len(enum_results) == 1
    assert enum_results[0].status == TestStatus.FAIL


@responses.activate
def test_username_enumeration_not_detected():
    """Same response for valid and invalid usernames should pass."""
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    responses.get(TARGET + "/login", status=200, body=LOGIN_PAGE)
    for _ in range(14):
        responses.post(TARGET + "/login", status=200, body="Invalid credentials")
    client = SessionClient(TARGET)
    module = AuthModule(credentials="admin:admin")
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    enum_results = [r for r in results if r.test_name == "username_enumeration"]
    assert len(enum_results) == 1
    assert enum_results[0].status == TestStatus.PASS
