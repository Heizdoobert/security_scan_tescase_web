"""Tests for SSL/TLS security module."""
import ssl
from unittest.mock import MagicMock, patch

from websec_test.modules.configuration.ssl_tls import SslTlsModule
from websec_test.results.models import TestStatus


def test_discover_https():
    """HTTPS URL should parse host and port correctly."""
    module = SslTlsModule()
    endpoints = module.discover(None, "https://example.com:8443/path")
    assert len(endpoints) == 1
    assert endpoints[0].host == "example.com"
    assert endpoints[0].port == 8443


def test_discover_default_port():
    """HTTPS URL without explicit port should default to 443."""
    module = SslTlsModule()
    endpoints = module.discover(None, "https://example.com/")
    assert endpoints[0].port == 443


def test_discover_http():
    """HTTP URL should use port from URL."""
    module = SslTlsModule()
    endpoints = module.discover(None, "http://localhost:8080/app")
    assert endpoints[0].host == "localhost"
    assert endpoints[0].port == 8080


@patch("websec_test.modules.configuration.ssl_tls.socket.create_connection")
@patch("websec_test.modules.configuration.ssl_tls.ssl.SSLContext")
def test_certificate_valid(mock_ssl_context, mock_create_connection):
    """Valid certificate with future expiry should pass."""
    mock_ctx = MagicMock()
    mock_ssl_context.return_value = mock_ctx
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = {"notAfter": "Dec 31 23:59:59 2030 GMT"}
    mock_wrap = MagicMock()
    mock_wrap.__enter__.return_value = mock_ssock
    mock_ctx.wrap_socket.return_value = mock_wrap
    mock_sock = MagicMock()
    mock_create_connection.return_value = mock_sock

    module = SslTlsModule()
    results = module._check_certificate("example.com", 443)
    assert len(results) == 1
    assert results[0].test_name == "certificate_valid"
    assert results[0].status == TestStatus.PASS


@patch("websec_test.modules.configuration.ssl_tls.socket.create_connection")
@patch("websec_test.modules.configuration.ssl_tls.ssl.SSLContext")
def test_certificate_expired(mock_ssl_context, mock_create_connection):
    """Expired certificate should fail."""
    mock_ctx = MagicMock()
    mock_ssl_context.return_value = mock_ctx
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = {"notAfter": "Dec 31 23:59:59 2020 GMT"}
    mock_wrap = MagicMock()
    mock_wrap.__enter__.return_value = mock_ssock
    mock_ctx.wrap_socket.return_value = mock_wrap
    mock_sock = MagicMock()
    mock_create_connection.return_value = mock_sock

    module = SslTlsModule()
    results = module._check_certificate("example.com", 443)
    assert len(results) == 1
    assert results[0].status == TestStatus.FAIL


@patch("websec_test.modules.configuration.ssl_tls.socket.create_connection")
@patch("websec_test.modules.configuration.ssl_tls.ssl.SSLContext")
def test_certificate_connection_refused(mock_ssl_context, mock_create_connection):
    """Connection refused should return ERROR."""
    mock_create_connection.side_effect = ConnectionRefusedError("Connection refused")

    module = SslTlsModule()
    results = module._check_certificate("example.com", 443)
    assert len(results) == 1
    assert results[0].status == TestStatus.ERROR


@patch("websec_test.modules.configuration.ssl_tls.socket.create_connection")
@patch("websec_test.modules.configuration.ssl_tls.ssl.SSLContext")
def test_weak_protocol_rejected(mock_ssl_context, mock_create_connection):
    """TLS 1.0 connection rejected should return PASS."""
    mock_ctx = MagicMock()
    mock_ssl_context.return_value = mock_ctx
    mock_ctx.wrap_socket.side_effect = ssl.SSLError("Handshake failed")

    module = SslTlsModule()
    results = module._check_weak_protocols("example.com", 443)
    assert len(results) == 1
    assert results[0].status == TestStatus.PASS


import responses
from websec_test.client.session import SessionClient

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"


@responses.activate
def test_hsts_preload_present():
    """HSTS with preload directive should pass."""
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={"Strict-Transport-Security": "max-age=31536000; preload"})
    client = SessionClient(TARGET)
    module = SslTlsModule()
    result = module._check_hsts_preload(client)
    assert result.test_name == "hsts_preload"
    assert result.status == TestStatus.PASS


@responses.activate
def test_hsts_preload_missing():
    """No HSTS header should fail."""
    responses.get(TARGET + "/", status=200, body="ok")
    client = SessionClient(TARGET)
    module = SslTlsModule()
    result = module._check_hsts_preload(client)
    assert result.status == TestStatus.FAIL


@responses.activate
def test_hsts_preload_without_directive():
    """HSTS without preload should warn."""
    responses.get(TARGET + "/", status=200, body="ok",
                  headers={"Strict-Transport-Security": "max-age=31536000"})
    client = SessionClient(TARGET)
    module = SslTlsModule()
    result = module._check_hsts_preload(client)
    assert result.status == TestStatus.WARN
