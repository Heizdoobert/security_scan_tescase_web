"""Tests for HTTP methods security module."""
import responses
from websec_test.modules.methods import MethodsModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"


@responses.activate
def test_options_safe_methods_pass():
    """OPTIONS with only safe methods should pass."""
    responses.add(responses.OPTIONS, TARGET + "/", status=200,
                  headers={"Allow": "GET, HEAD, POST"})
    responses.add("TRACE", TARGET + "/admin", status=405, body="Not Allowed")
    responses.add(responses.PUT, TARGET + "/", status=405, body="Not Allowed")
    responses.add(responses.DELETE, TARGET + "/", status=405, body="Not Allowed")
    responses.get(TARGET + "/", status=200, body="ok")
    responses.post(TARGET + "/", status=200, body="ok")
    client = SessionClient(TARGET)
    module = MethodsModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    for r in results:
        assert r.status == TestStatus.PASS, f"{r.test_name} should PASS"


@responses.activate
def test_dangerous_methods_detected():
    """TRACE, PUT, DELETE enabled should fail."""
    responses.add(responses.OPTIONS, TARGET + "/", status=200,
                  headers={"Allow": "GET, HEAD, POST, PUT, DELETE, TRACE"})
    responses.add("TRACE", TARGET + "/admin", status=200, body="TRACE OK")
    responses.add(responses.PUT, TARGET + "/", status=201, body="Created")
    responses.add(responses.DELETE, TARGET + "/", status=204, body="")
    responses.get(TARGET + "/", status=200, body="ok")
    responses.post(TARGET + "/", status=200, body="ok")
    client = SessionClient(TARGET)
    module = MethodsModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    fail_results = [r for r in results if r.status == TestStatus.FAIL]
    assert len(fail_results) >= 4  # OPTIONS, TRACE, PUT, DELETE


@responses.activate
def test_options_no_allow_header():
    """OPTIONS without Allow header should pass."""
    responses.add(responses.OPTIONS, TARGET + "/", status=200, body="")
    responses.add("TRACE", TARGET + "/admin", status=405, body="Not Allowed")
    responses.add(responses.PUT, TARGET + "/", status=405, body="Not Allowed")
    responses.add(responses.DELETE, TARGET + "/", status=405, body="Not Allowed")
    responses.get(TARGET + "/", status=200, body="ok")
    responses.post(TARGET + "/", status=200, body="ok")
    client = SessionClient(TARGET)
    module = MethodsModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    opt_results = [r for r in results if r.test_name == "options_allow_enumeration"]
    assert len(opt_results) == 1
    assert opt_results[0].status == TestStatus.PASS


@responses.activate
def test_verb_tampering_blocked():
    """Same response for GET and POST should mean tamper is blocked."""
    responses.add(responses.OPTIONS, TARGET + "/", status=200,
                  headers={"Allow": "GET, HEAD, POST"})
    responses.add("TRACE", TARGET + "/admin", status=405, body="Not Allowed")
    responses.add(responses.PUT, TARGET + "/", status=405, body="Not Allowed")
    responses.add(responses.DELETE, TARGET + "/", status=405, body="Not Allowed")
    responses.get(TARGET + "/", status=200, body="ok")
    responses.post(TARGET + "/", status=200, body="ok")  # Same status → tamper skipped
    client = SessionClient(TARGET)
    module = MethodsModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    tamper_results = [r for r in results if r.test_name == "verb_tampering"]
    assert len(tamper_results) == 1
    assert tamper_results[0].status == TestStatus.PASS


@responses.activate
def test_discover_returns_endpoints():
    """Discover should return 4 method-specific endpoints."""
    client = SessionClient(TARGET)
    module = MethodsModule()
    endpoints = module.discover(client, TARGET)
    assert len(endpoints) == 4
    http_methods = [e.http_method for e in endpoints]
    assert "OPTIONS" in http_methods
    assert "TRACE" in http_methods
    assert "PUT" in http_methods
    assert "DELETE" in http_methods
