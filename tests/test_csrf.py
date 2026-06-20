"""Tests for CSRF module."""
import responses
from websec_test.modules.csrf import CSRFModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"

FORM_WITH_CSRF = """<html><body>
    <form method="POST" action="/update">
        <input name="email"><input name="csrf_token" value="valid_token_123">
    </form>
</body></html>"""

FORM_WITHOUT_CSRF = """<html><body>
    <form method="POST" action="/update">
        <input name="email">
    </form>
</body></html>"""


@responses.activate
def test_discover_finds_forms():
    responses.get(TARGET + "/", status=200, body=FORM_WITH_CSRF)
    client = SessionClient(TARGET)
    module = CSRFModule()
    endpoints = module.discover(client, TARGET)
    assert len(endpoints) > 0


@responses.activate
def test_detects_missing_csrf_token():
    responses.get(TARGET + "/", status=200, body=FORM_WITHOUT_CSRF)
    responses.get(TARGET + "/update", status=200, body=FORM_WITHOUT_CSRF)
    client = SessionClient(TARGET)
    module = CSRFModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    missing = [r for r in results if r.test_name == "missing_csrf_token"]
    assert len(missing) > 0
    for r in missing:
        assert r.status == TestStatus.FAIL


@responses.activate
def test_passes_with_valid_csrf_token():
    responses.get(TARGET + "/", status=200, body=FORM_WITH_CSRF)
    responses.get(TARGET + "/update", status=200, body=FORM_WITH_CSRF)
    responses.post(TARGET + "/update", status=200, body="Success")
    client = SessionClient(TARGET)
    module = CSRFModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    missing = [r for r in results if r.test_name == "missing_csrf_token"]
    assert len(missing) > 0
    for r in missing:
        assert r.status == TestStatus.PASS


@responses.activate
def test_token_reuse_detection():
    responses.get(TARGET + "/", status=200, body=FORM_WITH_CSRF)
    responses.get(TARGET + "/update", status=200, body=FORM_WITH_CSRF)
    responses.post(TARGET + "/update", status=200, body="Success")
    client = SessionClient(TARGET)
    module = CSRFModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    reuse_tests = [r for r in results if r.test_name == "csrf_token_reuse"]
    assert len(reuse_tests) > 0
