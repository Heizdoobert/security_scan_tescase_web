"""Tests for CORS security module."""
import responses
from websec_test.modules.configuration.cors import CorsModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"


@responses.activate
def test_wildcard_origin_fail():
    """Wildcard ACAO should fail."""
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={"Access-Control-Allow-Origin": "*"})
    client = SessionClient(TARGET)
    module = CorsModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    target = [r for r in results if r.test_name == "wildcard_origin"]
    assert len(target) == 1
    assert target[0].status == TestStatus.FAIL


@responses.activate
def test_reflected_origin_fail():
    """Echoed Origin header should fail."""
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={"Access-Control-Allow-Origin": "https://evil.com"})
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={"Access-Control-Allow-Origin": "https://attacker.com"})
    client = SessionClient(TARGET)
    module = CorsModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    target = [r for r in results if r.test_name == "reflected_origin"]
    assert len(target) == 1
    assert target[0].status == TestStatus.FAIL


@responses.activate
def test_credentials_with_wildcard_fail():
    """Credentials=true with wildcard ACAO should fail critically."""
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={
                      "Access-Control-Allow-Origin": "*",
                      "Access-Control-Allow-Credentials": "true",
                  })
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={
                      "Access-Control-Allow-Origin": "*",
                      "Access-Control-Allow-Credentials": "true",
                  })
    client = SessionClient(TARGET)
    module = CorsModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    target = [r for r in results if r.test_name == "credentials_with_wildcard"]
    assert len(target) == 1
    assert target[0].status == TestStatus.FAIL


@responses.activate
def test_all_cors_headers_pass():
    """No CORS headers should all pass (no vulnerability)."""
    responses.get(TARGET + "/", status=200, body="ok")
    responses.get(TARGET + "/", status=200, body="ok")
    client = SessionClient(TARGET)
    module = CorsModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    for r in results:
        assert r.status == TestStatus.PASS, f"{r.test_name} should PASS"


@responses.activate
def test_discover_returns_root():
    """Discover should return a single root endpoint."""
    responses.get(TARGET + "/", status=200, body="ok")
    client = SessionClient(TARGET)
    module = CorsModule()
    endpoints = module.discover(client, TARGET)
    assert len(endpoints) == 1
    assert endpoints[0].url == "/"
