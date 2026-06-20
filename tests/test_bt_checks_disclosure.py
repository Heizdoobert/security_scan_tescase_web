"""Integration tests for disclosure check-level behavior tree."""
import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.disclosure import disclosure_check_specs, DisclosureModule
from websec_test.results.models import TestStatus

TARGET = "http://example.com"

# Non-root paths returned by DisclosureModule.discover()
_NONROOT_PATHS = [
    "/admin", "/WEB-INF/web.xml", "/backup",
    "/config", "/.env", "/console",
]


def _mock_all(root_headers=None, nonroot_status=403, nonroot_body="",
              stack_status=404, stack_body="<html><body>Not Found</body></html>"):
    """Register mock responses for all endpoints the disclosure checks hit."""
    responses.get(TARGET + "/", status=200, body="<html><body>root</body></html>",
                  headers=root_headers or {})
    for path in _NONROOT_PATHS:
        responses.get(TARGET + path, status=nonroot_status, body=nonroot_body)
    responses.get(TARGET + "/nonexistent_page_xyz_123_test",
                  status=stack_status, body=stack_body)


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
def test_disclosure_all_pass(blackboard, client):
    """No info headers, no directory listing, clean 404 -> all 6 PASS."""
    _mock_all()
    specs = disclosure_check_specs()
    tree = CheckTreeBuilder.build_module("disclosure", DisclosureModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 6
    for r in blackboard.results:
        assert r.status == TestStatus.PASS
        assert r.module == "disclosure"


@responses.activate
def test_disclosure_info_header_leak(blackboard, client):
    """Server header present on / -> info_header_server FAIL, others PASS."""
    _mock_all(root_headers={"Server": "Apache/2.4.41"})
    specs = disclosure_check_specs()
    tree = CheckTreeBuilder.build_module("disclosure", DisclosureModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    server = [r for r in blackboard.results if r.test_name == "info_header_server"]
    assert len(server) == 1 and server[0].status == TestStatus.FAIL

    # Other info header checks still pass
    for r in blackboard.results:
        if r.test_name.startswith("info_header_") and r.test_name != "info_header_server":
            assert r.status == TestStatus.PASS


@responses.activate
def test_disclosure_directory_listing(blackboard, client):
    """Non-root endpoint returns directory listing content -> FAIL."""
    dl_body = "<html><title>Index of /admin</title><body>Index of /admin</body></html>"
    _mock_all(nonroot_status=200, nonroot_body=dl_body)
    specs = disclosure_check_specs()
    tree = CheckTreeBuilder.build_module("disclosure", DisclosureModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    dl = [r for r in blackboard.results if r.test_name == "directory_listing"]
    assert len(dl) == 1 and dl[0].status == TestStatus.FAIL

    st = [r for r in blackboard.results if r.test_name == "stack_trace_error"]
    assert len(st) == 1 and st[0].status == TestStatus.PASS


@responses.activate
def test_disclosure_stack_trace(blackboard, client):
    """Nonexistent endpoint returns 500 with traceback -> FAIL."""
    trace_body = "<html><body><pre>Traceback: at System.Web...</pre></body></html>"
    _mock_all(stack_status=500, stack_body=trace_body)
    specs = disclosure_check_specs()
    tree = CheckTreeBuilder.build_module("disclosure", DisclosureModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    st = [r for r in blackboard.results if r.test_name == "stack_trace_error"]
    assert len(st) == 1 and st[0].status == TestStatus.FAIL

    dl = [r for r in blackboard.results if r.test_name == "directory_listing"]
    assert len(dl) == 1 and dl[0].status == TestStatus.PASS
