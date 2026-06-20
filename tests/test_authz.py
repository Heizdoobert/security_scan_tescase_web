"""Tests for authorization module."""
import responses
from websec_test.modules.authz import AuthorizationModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus
from websec_test.config.payloads import COMMON_PATHS

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"


@responses.activate
def test_forced_browsing_detects_open_admin():
    for path in COMMON_PATHS:
        responses.get(TARGET + path, status=200, body="<html><body>" + path + " content that is longer than fifty characters for sure</body></html>")
    for uid in range(1, 4):
        for p in [f"/user/{uid}", f"/profile/{uid}", f"/account/{uid}"]:
            responses.get(TARGET + p, status=404, body="Not found")
    responses.get(TARGET + "/", status=200, body="<html>Home</html>")
    client = SessionClient(TARGET)
    module = AuthorizationModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    browsed = [r for r in results if r.test_name == "forced_browsing" and r.status == TestStatus.FAIL]
    assert len(browsed) > 0


@responses.activate
def test_forced_browsing_secure():
    for path in COMMON_PATHS:
        responses.get(TARGET + path, status=404, body="Not found")
    for uid in range(1, 4):
        for p in [f"/user/{uid}", f"/profile/{uid}", f"/account/{uid}"]:
            responses.get(TARGET + p, status=404, body="Not found")
    responses.get(TARGET + "/", status=200, body="<html>Home</html>")
    client = SessionClient(TARGET)
    module = AuthorizationModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    for r in results:
        if r.test_name == "forced_browsing":
            assert r.status == TestStatus.PASS


@responses.activate
def test_idor_check():
    for path in COMMON_PATHS:
        responses.get(TARGET + path, status=404, body="Not found")
    for i in range(1, 4):
        responses.get(TARGET + f"/user/{i}", status=200, body="User data " * 20)
        responses.get(TARGET + f"/profile/{i}", status=404, body="Not found")
        responses.get(TARGET + f"/account/{i}", status=404, body="Not found")
    responses.get(TARGET + "/", status=200, body="<html>Home</html>")
    client = SessionClient(TARGET)
    module = AuthorizationModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    idor_tests = [r for r in results if r.test_name == "idor_check"]
    assert len(idor_tests) > 0
