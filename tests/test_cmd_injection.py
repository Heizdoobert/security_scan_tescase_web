"""Tests for command injection module."""
import responses
from websec_test.modules.injection.cmd_injection import CmdInjectionModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus
from websec_test.modules._shared import parse_form_inputs

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
    module = CmdInjectionModule()
    endpoints = parse_form_inputs(client.get(TARGET + "/").text)
    assert len(endpoints) > 0


@responses.activate
def test_cmd_injection_detected():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(TARGET + "/search?q=%3B+ls", status=200,
                  body="uid=1000(john) gid=1000(john)")
    client = SessionClient(TARGET)
    module = CmdInjectionModule()
    endpoints = parse_form_inputs(client.get(TARGET + "/").text)
    results = module.test(client, TARGET, endpoints)
    cmd_tests = [r for r in results if r.test_name == "cmd_injection"]
    assert len(cmd_tests) > 0


@responses.activate
def test_no_false_positive():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(TARGET + "/search?q=test", status=200,
                  body="Results for: test (sanitized)")
    client = SessionClient(TARGET)
    module = CmdInjectionModule()
    endpoints = parse_form_inputs(client.get(TARGET + "/").text)
    results = module.test(client, TARGET, endpoints)
    for r in results:
        assert r.status != TestStatus.ERROR
