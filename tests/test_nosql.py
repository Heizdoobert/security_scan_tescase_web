"""Tests for NoSQL injection module."""
import re
import responses
from websec_test.modules.injection.nosql import NosqlModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus
from websec_test.modules._shared import parse_form_inputs

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"

SEARCH_PAGE = """<html><body>
    <form method="GET" action="/search">
        <input name="q">
    </form>
</body></html>"""

BASELINE_URL = TARGET + "/search?q=invalid__test__value"


@responses.activate
def test_discover_finds_form():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    client = SessionClient(TARGET)
    module = NosqlModule()
    endpoints = parse_form_inputs(client.get(TARGET + "/").text)
    assert len(endpoints) > 0


@responses.activate
def test_nosql_payloads_in_form_fields():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(BASELINE_URL, status=200, body="invalid password")
    responses.get(TARGET + "/search?q%5B%24ne%5D=", status=200,
                  body="invalid password")
    client = SessionClient(TARGET)
    module = NosqlModule()
    endpoints = parse_form_inputs(client.get(TARGET + "/").text)
    results = module.test(client, TARGET, endpoints)
    nosql_results = [r for r in results if r.test_name == "nosql_injection"]
    assert len(nosql_results) > 0


@responses.activate
def test_nosql_bypass_detected():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(BASELINE_URL, status=200, body="invalid password")
    responses.get(TARGET + "/search?q%5B%24ne%5D=",
                  status=200, body="welcome admin, logged in")
    client = SessionClient(TARGET)
    module = NosqlModule()
    endpoints = parse_form_inputs(client.get(TARGET + "/").text)
    results = module.test(client, TARGET, endpoints)
    nosql_bypass = [r for r in results if r.test_name == "nosql_injection"
                    and r.status == TestStatus.FAIL]
    assert len(nosql_bypass) > 0


@responses.activate
def test_nosql_no_bypass():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(BASELINE_URL, status=200, body="invalid password")
    responses.get(TARGET + "/search?q%5B%24ne%5D=",
                  status=200, body="invalid password")
    responses.add(responses.POST, re.compile(TARGET + "/search.*"),
                  status=200, body="invalid password")
    client = SessionClient(TARGET)
    module = NosqlModule()
    endpoints = parse_form_inputs(client.get(TARGET + "/").text)
    results = module.test(client, TARGET, endpoints)
    nosql_results = [r for r in results if r.test_name == "nosql_injection"]
    assert any(r.status == TestStatus.PASS for r in nosql_results)


@responses.activate
def test_nosql_connection_error():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(BASELINE_URL, status=200, body="invalid password")
    client = SessionClient(TARGET)
    module = NosqlModule()
    endpoints = parse_form_inputs(client.get(TARGET + "/").text)
    results = module.test(client, TARGET, endpoints)
    assert len(results) > 0
