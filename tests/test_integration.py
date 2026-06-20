"""Integration test — run the full tool against a mock server.

Requires `pip install flask` (dev dependency). Starts a local Flask app
with deliberate vulnerabilities, runs the websec CLI against it, and
validates the JSON report.
"""
import subprocess
import sys
import json
import tempfile
from pathlib import Path
import pytest
import socket
import threading
import time

VULNERABLE_APP_CODE = '''
import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/")
def index():
    return """<html><body>
        <form method="GET" action="/search">
            <input name="q">
        </form>
        <form method="POST" action="/update">
            <input name="email">
            <input name="csrf_token" value="static_token">
        </form>
    </body></html>"""

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"Results for: {q}"

@app.route("/update", methods=["POST"])
def update():
    return "Updated"

@app.route("/admin")
def admin():
    return "Admin panel - no auth required"

@app.route("/WEB-INF/web.xml")
def webxml():
    return "<web-app>config</web-app>"

@app.after_request
def add_vuln_headers(response):
    response.headers["X-XSS-Protection"] = "0"
    return response

if __name__ == "__main__":
    app.run(port=int(os.environ.get("FLASK_RUN_PORT", 0)))
'''


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def vulnerable_server():
    """Start a vulnerable Flask server on a random port."""
    port = find_free_port()
    # Write the app to a temp file and run it
    with tempfile.TemporaryDirectory() as tmp:
        app_path = Path(tmp) / "vuln_app.py"
        app_path.write_text(VULNERABLE_APP_CODE)

        proc = subprocess.Popen(
            [sys.executable, str(app_path)],
            env={**__import__('os').environ, "FLASK_RUN_PORT": str(port)},
            cwd=tmp,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        target = f"http://localhost:{port}"
        try:
            yield target
        finally:
            proc.terminate()
            proc.wait()


def test_integration_full_run(vulnerable_server):
    """Run the full websec tool against the vulnerable server and check JSON output."""
    with tempfile.TemporaryDirectory() as out_dir:
        result = subprocess.run(
            [sys.executable, "-m", "websec_test.main",
             "--target", vulnerable_server,
             "--all",
             "--output", out_dir],
            capture_output=True, text=True,
        )
        assert result.returncode in (0, 1), f"STDERR: {result.stderr}"

        json_files = list(Path(out_dir).glob("*.json"))
        assert len(json_files) == 1, f"No JSON report found in {out_dir}"

        with open(json_files[0]) as f:
            report = json.load(f)

        assert report["target"] == vulnerable_server
        assert report["summary"]["total"] > 0
        assert len(report["results"]) > 0
        assert report["summary"]["fail"] > 0, "Expected failures against vulnerable server"


def test_integration_cli_help():
    """Test that --help works."""
    result = subprocess.run(
        [sys.executable, "-m", "websec_test.main", "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "Web Security Testing CLI" in result.stdout
