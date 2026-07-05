"""Tests for information disclosure module."""
import responses
from websec_test.modules.configuration.disclosure import DisclosureModule
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"


@responses.activate
def test_info_headers_absent_pass():
    """No sensitive headers should return all passes."""
    responses.get(TARGET + "/", status=200, body="<html></html>")
    responses.get(TARGET + "/nonexistent_page_xyz_123_test", status=404, body="Not Found")
    client = SessionClient(TARGET)
    module = DisclosureModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    info_results = [r for r in results if r.test_name.startswith("info_header_")]
    for r in info_results:
        assert r.status == TestStatus.PASS, f"{r.test_name} should PASS"


@responses.activate
def test_info_headers_present_fail():
    """Sensitive headers present should fail."""
    responses.get(TARGET + "/", status=200, body="<html></html>",
                  headers={"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4"})
    responses.get(TARGET + "/nonexistent_page_xyz_123_test", status=404, body="Not Found")
    client = SessionClient(TARGET)
    module = DisclosureModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    info_results = [r for r in results if r.test_name.startswith("info_header_")]
    fail_results = [r for r in info_results if r.status == TestStatus.FAIL]
    assert len(fail_results) >= 2  # At least Server and X-Powered-By


@responses.activate
def test_directory_listing_detected():
    """Response with 'Index of' should detect directory listing."""
    responses.get(TARGET + "/", status=200, body="<html></html>")
    responses.get(TARGET + "/admin", status=200, body="<title>Index of /admin</title>")
    responses.get(TARGET + "/nonexistent_page_xyz_123_test", status=404, body="Not Found")
    client = SessionClient(TARGET)
    module = DisclosureModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    dl_results = [r for r in results if r.test_name == "directory_listing"]
    fail_results = [r for r in dl_results if r.status == TestStatus.FAIL]
    assert len(fail_results) > 0


@responses.activate
def test_no_directory_listing():
    """Normal response should not detect directory listing."""
    responses.get(TARGET + "/", status=200, body="<html><body>Welcome</body></html>")
    responses.get(TARGET + "/nonexistent_page_xyz_123_test", status=404, body="Not Found")
    client = SessionClient(TARGET)
    module = DisclosureModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    dl_results = [r for r in results if r.test_name == "directory_listing"]
    if dl_results:
        for r in dl_results:
            assert r.status == TestStatus.PASS


@responses.activate
def test_stack_trace_detected():
    """500 error with stack trace content should fail."""
    responses.get(TARGET + "/", status=200, body="<html></html>")
    responses.get(TARGET + "/nonexistent_page_xyz_123_test",
                  status=500, body="<html>Traceback: ZeroDivisionError</html>")
    client = SessionClient(TARGET)
    module = DisclosureModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    stack_results = [r for r in results if r.test_name == "stack_trace_error"]
    assert len(stack_results) == 1
    assert stack_results[0].status == TestStatus.FAIL


@responses.activate
def test_stack_trace_clean():
    """404 without stack trace should pass."""
    responses.get(TARGET + "/", status=200, body="<html></html>")
    responses.get(TARGET + "/nonexistent_page_xyz_123_test",
                  status=404, body="<html>Not Found</html>")
    client = SessionClient(TARGET)
    module = DisclosureModule()
    endpoints = module.discover(client, TARGET)
    results = module.test(client, TARGET, endpoints)
    stack_results = [r for r in results if r.test_name == "stack_trace_error"]
    assert len(stack_results) == 1
    assert stack_results[0].status == TestStatus.PASS
