"""Live auth integration tests against sandbox target."""
import os
import json

import pytest
import requests

from websec_test.client.session import SessionClient
from websec_test.modules.authentication.auth import AuthModule
from websec_test.results.collector import ResultCollector
from websec_test.results.models import TestStatus
from websec_test.results.reporter import Reporter

SANDBOX_TARGET = os.getenv("WEBSEC_LIVE_TARGET", "http://localhost:8080/note/login")
AUTH_CREDENTIALS = os.getenv("WEBSEC_LIVE_AUTH", "admin:admin")


def _sandbox_available() -> bool:
    try:
        response = requests.get(SANDBOX_TARGET, timeout=3)
        return response.status_code < 500
    except requests.RequestException:
        return False


pytestmark = [pytest.mark.integration, pytest.mark.skipif(
    not _sandbox_available(), reason=f"Sandbox target unavailable: {SANDBOX_TARGET}")]


def test_live_discover_login_form():
    client = SessionClient(SANDBOX_TARGET)
    module = AuthModule(credentials=AUTH_CREDENTIALS)
    endpoints = module.discover(client, SANDBOX_TARGET)
    assert endpoints, "No login endpoint discovered on live sandbox"
    assert any("login" in endpoint.url.lower() for endpoint in endpoints)


def test_live_auth_results_are_real():
    client = SessionClient(SANDBOX_TARGET)
    module = AuthModule(credentials=AUTH_CREDENTIALS)
    endpoints = module.discover(client, SANDBOX_TARGET)
    results = module.test(client, SANDBOX_TARGET, endpoints)
    assert results, "Live scan returned no auth results"
    assert all(result.status in {TestStatus.PASS, TestStatus.FAIL, TestStatus.WARN, TestStatus.ERROR}
               for result in results)
    assert any(result.test_name == "rate_limiting" for result in results)


def test_live_json_report_contains_real_response_data(tmp_path):
    client = SessionClient(SANDBOX_TARGET)
    module = AuthModule(credentials=AUTH_CREDENTIALS)
    endpoints = module.discover(client, SANDBOX_TARGET)
    results = module.test(client, SANDBOX_TARGET, endpoints)

    collector = ResultCollector()
    for result in results:
        collector.add(result)

    report_path = Reporter(collector, target=SANDBOX_TARGET, duration=0.0).to_json(tmp_path)
    report = json.loads(open(report_path, encoding="utf-8").read())

    assert report["target"] == SANDBOX_TARGET
    assert report["summary"]["total"] == len(results)
    assert report["results"], "JSON report has no results"
    assert all(entry["endpoint"] for entry in report["results"])
    assert all(entry["actual"] for entry in report["results"])