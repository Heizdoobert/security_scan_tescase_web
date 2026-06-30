"""Integration test — runs websec_test against a live Flask app with intentional vulnerabilities.

Starts a Flask server in a background thread, runs the full scan pipeline,
and verifies that known vulnerabilities are detected.
"""
import threading
import time
import pytest
import requests

TARGET = "http://127.0.0.1:9876"


def _vuln_app():
    """Build the vulnerable Flask application."""
    from flask import Flask, request, Response

    app = Flask(__name__)

    @app.route("/")
    def index():
        return "<html><body>Welcome</body></html>"

    @app.route("/login")
    def login():
        return """<html><body>
            <form method="POST" action="/login">
                <input name="password" type="password">
                <input type="submit">
            </form>
        </body></html>"""

    @app.route("/login", methods=["POST"])
    def login_post():
        return "Invalid credentials", 401

    @app.route("/admin")
    def admin():
        return "<html><body><h1>Admin panel</h1></body></html>"

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        return f"Results for: {q}"

    @app.route("/debug")
    def debug():
        return Response(
            "Traceback: ValueError at /debug",
            headers={"X-Powered-By": "Flask 1.0", "Server": "Werkzeug/2.0"},
        )

    return app


@pytest.fixture(scope="module")
def vulnerable_app():
    """Start Flask server with intentional security gaps on port 9876."""
    app = _vuln_app()
    thread = threading.Thread(
        target=app.run, kwargs={"port": 9876, "debug": False, "use_reloader": False},
        daemon=True,
    )
    thread.start()
    time.sleep(1)
    yield


def test_target_reachable(vulnerable_app):
    resp = requests.get(TARGET, timeout=5)
    assert resp.status_code == 200


def test_headers_fail_on_vulnerable_app(vulnerable_app):
    from websec_test.client.session import SessionClient
    from websec_test.modules.headers import HeadersModule
    from websec_test.results.models import TestStatus

    client = SessionClient(TARGET)
    module = HeadersModule()
    eps = module.discover(client, TARGET)
    results = module.test(client, TARGET, eps)
    fails = [r for r in results if r.status == TestStatus.FAIL]
    assert len(fails) >= 7, f"Expected >=7 header failures, got {len(fails)}"


def test_disclosure_fails_on_vulnerable_app(vulnerable_app):
    from websec_test.client.session import SessionClient
    from websec_test.modules.disclosure import DisclosureModule
    from websec_test.results.models import TestStatus

    client = SessionClient(TARGET)
    module = DisclosureModule()
    eps = module.discover(client, TARGET)
    results = module.test(client, TARGET, eps)
    fails = [r for r in results if r.status == TestStatus.FAIL]
    assert len(fails) >= 1, f"Expected >=1 disclosure failure, got {len(fails)}"


def test_full_scan_exit_code(vulnerable_app):
    """End-to-end: scan should exit 1 because vulnerable app has findings."""
    import sys
    from websec_test.main import run, parse_args

    args = parse_args(["--target", TARGET, "--all", "--output", "./reports"])
    with pytest.raises(SystemExit) as exc:
        run(args)
    assert exc.value.code == 1, "Expected exit code 1 (vulnerabilities found)"


def test_bt_check_level_exit_code(vulnerable_app):
    """Check-level BT scan should also exit 1."""
    import sys
    from websec_test.main import run, parse_args

    args = parse_args(["--target", TARGET, "--all", "--check-level", "--output", "./reports"])
    with pytest.raises(SystemExit) as exc:
        run(args)
    assert exc.value.code == 1, "Expected exit code 1 (vulnerabilities found)"
