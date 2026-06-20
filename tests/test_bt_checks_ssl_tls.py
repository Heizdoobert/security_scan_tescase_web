"""Integration tests for ssl_tls check-level behavior tree."""
import ssl
from unittest.mock import MagicMock, patch

import pytest
import responses
from websec_test.client.session import SessionClient
from websec_test.engine.nodes import Blackboard, NodeStatus
from websec_test.engine.builder import CheckTreeBuilder
from websec_test.modules.ssl_tls import ssl_tls_check_specs, SslTlsModule
from websec_test.results.models import TestStatus

TARGET = "https://example.com"


def _make_ssl_mocks():
    """Build standard SSL mocks and return them.

    Returns a 3-tuple (mock_ctx, mock_ssock, mock_sock) that callers
    can further configure (e.g. set getpeercert, side_effect, etc).
    """
    mock_ctx = MagicMock()
    mock_ssock = MagicMock()
    mock_sock = MagicMock()

    mock_wrap = MagicMock()
    mock_wrap.__enter__.return_value = mock_ssock
    mock_ctx.wrap_socket.return_value = mock_wrap

    return mock_ctx, mock_ssock, mock_sock


@pytest.fixture
def client():
    return SessionClient(TARGET)


@pytest.fixture
def blackboard(client):
    return Blackboard(client=client, target=TARGET)


@responses.activate
@patch("websec_test.modules.ssl_tls.socket.create_connection")
@patch("websec_test.modules.ssl_tls.ssl.SSLContext")
def test_ssl_tls_all_pass(mock_ssl_context, mock_create_connection, blackboard, client):
    """Valid cert, TLS 1.0 rejected, HSTS with preload -> all PASS."""
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={"Strict-Transport-Security": "max-age=31536000; preload"})

    ctx, ssock, sock = _make_ssl_mocks()
    ssock.getpeercert.return_value = {"notAfter": "Dec 31 23:59:59 2030 GMT"}

    def ctx_side_effect(*args, **kwargs):
        return ctx
    mock_ssl_context.side_effect = ctx_side_effect
    mock_create_connection.return_value = sock

    # Second SSL context (for weak protocol check) — raises SSLError (rejected)
    ctx2 = MagicMock()
    ctx2.wrap_socket.side_effect = ssl.SSLError("Handshake failed")

    def ctx_side_effect_2(*args, **kwargs):
        # First call returns ctx, second returns ctx2
        ctx_side_effect_2.call_count = getattr(ctx_side_effect_2, "call_count", 0) + 1
        if ctx_side_effect_2.call_count == 1:
            return ctx
        return ctx2

    mock_ssl_context.side_effect = ctx_side_effect_2

    specs = ssl_tls_check_specs()
    tree = CheckTreeBuilder.build_module("ssl_tls", SslTlsModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS
    assert len(blackboard.results) == 3
    for r in blackboard.results:
        assert r.module == "ssl_tls"

    cert = next(r for r in blackboard.results if r.test_name == "certificate_valid")
    weak = next(r for r in blackboard.results if r.test_name == "weak_protocol_tls_1_0")
    hsts = next(r for r in blackboard.results if r.test_name == "hsts_preload")
    assert cert.status == TestStatus.PASS
    assert weak.status == TestStatus.PASS
    assert hsts.status == TestStatus.PASS


@responses.activate
@patch("websec_test.modules.ssl_tls.socket.create_connection")
@patch("websec_test.modules.ssl_tls.ssl.SSLContext")
def test_ssl_tls_certificate_expired(mock_ssl_context, mock_create_connection, blackboard, client):
    """Expired certificate -> certificate_valid FAIL."""
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={"Strict-Transport-Security": "max-age=31536000; preload"})

    ctx, ssock, sock = _make_ssl_mocks()
    ssock.getpeercert.return_value = {"notAfter": "Dec 31 23:59:59 2020 GMT"}
    mock_ssl_context.return_value = ctx
    mock_create_connection.return_value = sock

    specs = ssl_tls_check_specs()
    tree = CheckTreeBuilder.build_module("ssl_tls", SslTlsModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    cert = next(r for r in blackboard.results if r.test_name == "certificate_valid")
    assert cert.status == TestStatus.FAIL


@responses.activate
@patch("websec_test.modules.ssl_tls.socket.create_connection")
@patch("websec_test.modules.ssl_tls.ssl.SSLContext")
def test_ssl_tls_weak_protocol_accepted(mock_ssl_context, mock_create_connection, blackboard, client):
    """TLS 1.0 accepted -> weak_protocol_tls_1_0 FAIL."""
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={"Strict-Transport-Security": "max-age=31536000; preload"})

    # Certificate: valid
    ctx = MagicMock()
    ssock = MagicMock()
    ssock.getpeercert.return_value = {"notAfter": "Dec 31 23:59:59 2030 GMT"}
    wrap_ok = MagicMock()
    wrap_ok.__enter__.return_value = ssock
    ctx.wrap_socket.return_value = wrap_ok
    mock_ssl_context.return_value = ctx
    mock_create_connection.return_value = MagicMock()

    specs = ssl_tls_check_specs()
    tree = CheckTreeBuilder.build_module("ssl_tls", SslTlsModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    weak = next(r for r in blackboard.results if r.test_name == "weak_protocol_tls_1_0")
    assert weak.status == TestStatus.FAIL


@responses.activate
@patch("websec_test.modules.ssl_tls.socket.create_connection")
@patch("websec_test.modules.ssl_tls.ssl.SSLContext")
def test_ssl_tls_hsts_missing(mock_ssl_context, mock_create_connection, blackboard, client):
    """No HSTS header -> hsts_preload FAIL."""
    responses.get(TARGET + "/", status=200, body="ok")

    ctx, ssock, sock = _make_ssl_mocks()
    ssock.getpeercert.return_value = {"notAfter": "Dec 31 23:59:59 2030 GMT"}

    def ctx_side_effect(*args, **kwargs):
        ctx_side_effect.call_count = getattr(ctx_side_effect, "call_count", 0) + 1
        if ctx_side_effect.call_count == 1:
            return ctx
        ctx2 = MagicMock()
        ctx2.wrap_socket.side_effect = ssl.SSLError("Handshake failed")
        return ctx2

    mock_ssl_context.side_effect = ctx_side_effect
    mock_create_connection.return_value = sock

    specs = ssl_tls_check_specs()
    tree = CheckTreeBuilder.build_module("ssl_tls", SslTlsModule().discover, specs)
    result = tree.tick(blackboard)
    assert result == NodeStatus.SUCCESS

    hsts = next(r for r in blackboard.results if r.test_name == "hsts_preload")
    assert hsts.status == TestStatus.FAIL
