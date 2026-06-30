"""Tests for SQL injection module."""
import responses
from websec_test.modules.injection.sqli import SqliModule
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
    module = SqliModule()
    endpoints = module.discover(client, TARGET)
    assert len(endpoints) > 0


@responses.activate
def test_sqli_detects_reflected_error():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(TARGET + "/search?q=%27+OR+%271%27%3D%271", status=200,
                  body="SQL syntax error near 'OR 1=1'")
    client = SessionClient(TARGET)
    module = SqliModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    sqli_tests = [r for r in results if r.test_name == "sqli_detection"]
    assert len(sqli_tests) > 0


@responses.activate
def test_no_false_positive():
    responses.get(TARGET + "/", status=200, body=SEARCH_PAGE)
    responses.get(TARGET + "/search?q=test", status=200,
                  body="Results for: test (sanitized)")
    client = SessionClient(TARGET)
    module = SqliModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    for r in results:
        assert r.status != TestStatus.ERROR
