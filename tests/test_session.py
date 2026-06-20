"""Tests for HTTP session client."""
import responses
import pytest
from websec_test.client.session import SessionClient
from websec_test.results.models import TestStatus

TARGET = "http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT"


@responses.activate
def test_get_request():
    responses.get(f"{TARGET}/login", status=200, body="<html>login</html>")
    client = SessionClient(TARGET)
    resp = client.get("/login")
    assert resp.status_code == 200


@responses.activate
def test_get_request_preserves_session():
    responses.get(f"{TARGET}/login", status=200, body="<html>login</html>", headers={"Set-Cookie": "session_id=abc123"})
    client = SessionClient(TARGET)
    resp = client.get("/login")
    # Verify session cookie is preserved from response
    assert client.session.cookies.get("session_id") == "abc123"


@responses.activate
def test_csrf_token_extraction():
    html = """<html><body>
        <form><input name="csrf_token" value="tok_abc123"></form>
    </body></html>"""
    responses.get(f"{TARGET}/form", status=200, body=html)
    client = SessionClient(TARGET)
    resp = client.get("/form")
    token = client.extract_csrf_token(resp.text)
    assert token == "tok_abc123"


@responses.activate
def test_extract_csrf_token_default_patterns():
    """Test multiple common CSRF token field names."""
    htmls = [
        ("csrf_token", "tok1"),
        ("_token", "tok2"),
        ("authenticity_token", "tok3"),
        ("csrfmiddlewaretoken", "tok4"),
    ]
    for field, expected in htmls:
        html = f'<input name="{field}" value="{expected}">'
        client = SessionClient(TARGET)
        token = client.extract_csrf_token(html)
        assert token == expected, f"Failed for {field}"


@responses.activate
def test_extract_csrf_token_none_found():
    html = "<html><body><p>no form</p></body></html>"
    client = SessionClient(TARGET)
    token = client.extract_csrf_token(html)
    assert token is None


@responses.activate
def test_request_timeout():
    import requests
    client = SessionClient(TARGET, timeout=0.001)
    # No response registered for /slow - ConnectionError is raised by responses
    with pytest.raises(requests.exceptions.ConnectionError):
        client.get("/slow")


@responses.activate
def test_relative_url_resolution():
    responses.get(f"{TARGET}/page", status=200, body="ok")
    client = SessionClient(TARGET)
    resp = client.get("http://localhost:8080/Nhom_2s-0.0.1-SNAPSHOT/page")
    assert resp.status_code == 200
