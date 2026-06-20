"""Tests for security headers module."""
import responses
from websec_test.modules.headers import HeadersModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"

REQUIRED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


@responses.activate
def test_missing_all_headers():
    responses.get(TARGET + "/", status=200, body="<html></html>")
    client = SessionClient(TARGET)
    module = HeadersModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    assert len(results) == len(REQUIRED_HEADERS)
    for r in results:
        assert r.status == TestStatus.FAIL


@responses.activate
def test_all_headers_present():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }
    responses.get(TARGET + "/", status=200, body="<html></html>", headers=headers)
    client = SessionClient(TARGET)
    module = HeadersModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    for r in results:
        assert r.status == TestStatus.PASS, f"{r.test_name} should PASS"


@responses.activate
def test_partial_headers():
    headers = {"X-Frame-Options": "DENY"}
    responses.get(TARGET + "/", status=200, body="<html></html>", headers=headers)
    client = SessionClient(TARGET)
    module = HeadersModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    pass_count = sum(1 for r in results if r.status == TestStatus.PASS)
    fail_count = sum(1 for r in results if r.status == TestStatus.FAIL)
    assert pass_count == 1
    assert fail_count == len(REQUIRED_HEADERS) - 1


@responses.activate
def test_recommendation_present_on_fail():
    responses.get(TARGET + "/", status=200, body="<html></html>")
    client = SessionClient(TARGET)
    module = HeadersModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    for r in results:
        if r.status == TestStatus.FAIL:
            assert len(r.recommendation) > 0


@responses.activate
def test_discover_returns_root():
    responses.get(TARGET + "/", status=200, body="<html></html>")
    client = SessionClient(TARGET)
    module = HeadersModule()
    endpoints = module.discover(client, TARGET)
    assert len(endpoints) == 1
    assert endpoints[0].url == "/"
