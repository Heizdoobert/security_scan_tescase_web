"""Tests for mongodb_check companion script."""
import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from websec_test.mongodb_check import (
    find_mongosh,
    run_mongosh_eval,
    run_all_checks,
)


# ── find_mongosh tests ──────────────────────────────────────────────────────

@patch("websec_test.mongodb_check.shutil.which", return_value=None)
@patch("websec_test.mongodb_check.os.path.isfile", return_value=False)
@patch("websec_test.mongodb_check.glob.glob", return_value=[])
def test_mongosh_not_found_via_any_method(mock_glob, mock_isfile, mock_which):
    """All discovery methods fail → find_mongosh returns None."""
    assert find_mongosh() is None


@patch("websec_test.mongodb_check.shutil.which", return_value=None)
@patch("websec_test.mongodb_check.os.path.isfile")
def test_mongosh_found_in_local_bin(mock_isfile, mock_which):
    """find_mongosh finds mongosh.exe in .\\mongosh-bin\\."""
    def isfile_side_effect(path):
        return "mongosh-bin\\mongosh.exe" in path
    mock_isfile.side_effect = isfile_side_effect
    result = find_mongosh()
    assert result is not None
    assert "mongosh.exe" in result


@patch("websec_test.mongodb_check.os.path.isfile", return_value=True)
def test_mongosh_explicit_path_valid(mock_isfile):
    """Explicit --mongosh-path to existing file returns that path."""
    result = find_mongosh(mongosh_path=r"C:\tools\mongosh.exe")
    assert result == r"C:\tools\mongosh.exe"


def test_mongosh_explicit_path_invalid():
    """Explicit path to non-existent file returns None."""
    result = find_mongosh(mongosh_path=r"C:\nonexistent\mongosh.exe")
    assert result is None


# ── run_mongosh_eval tests ──────────────────────────────────────────────────

@patch("websec_test.mongodb_check.subprocess.run")
def test_run_mongosh_eval_success(mock_run):
    """Successful mongosh eval returns parsed JSON."""
    mock_run.return_value = MagicMock(
        returncode=0, stdout='{"ok": 1}\n', stderr=""
    )
    result = run_mongosh_eval("mongodb://localhost:27017", "JSON.stringify(db.adminCommand('ping'))")
    assert result == {"ok": 1}


@patch("websec_test.mongodb_check.subprocess.run")
def test_run_mongosh_eval_takes_last_line(mock_run):
    """mongosh warnings before JSON are ignored; last line is parsed."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="Warning: found non-matching index spec\n{\"ok\": 1}\n",
        stderr=""
    )
    result = run_mongosh_eval("mongodb://localhost:27017", "JSON.stringify(db.adminCommand('ping'))")
    assert result == {"ok": 1}


@patch("websec_test.mongodb_check.subprocess.run")
def test_run_mongosh_eval_nonzero_exit(mock_run):
    """Non-zero returncode raises CalledProcessError."""
    mock_run.return_value = MagicMock(
        returncode=1, stdout="", stderr="command not found"
    )
    with pytest.raises(subprocess.CalledProcessError):
        run_mongosh_eval("mongodb://localhost:27017", "bad command")


@patch("websec_test.mongodb_check.subprocess.run")
def test_run_mongosh_eval_timeout(mock_run):
    """Timeout raises TimeoutExpired."""
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="mongosh", timeout=5)
    with pytest.raises(subprocess.TimeoutExpired):
        run_mongosh_eval("mongodb://localhost:27017", "db.adminCommand('ping')", timeout=5)


# ── run_all_checks tests ────────────────────────────────────────────────────

@patch("websec_test.mongodb_check.run_mongosh_eval")
def test_ping_success(mock_eval):
    """Connection check passes when ping returns ok=1."""
    mock_eval.return_value = {"ok": 1}
    results = run_all_checks("mongodb://localhost:27017", mongosh_path="mongosh")
    ping_result = [r for r in results if r["test_name"] == "connection_check"]
    assert len(ping_result) == 1
    assert ping_result[0]["status"] == "pass"


@patch("websec_test.mongodb_check.run_mongosh_eval")
def test_ping_connection_refused(mock_eval):
    """Connection check fails when ping raises error."""
    mock_eval.side_effect = subprocess.CalledProcessError(1, [], stderr="Connection refused")
    results = run_all_checks("mongodb://localhost:27017", mongosh_path="mongosh")
    ping_result = [r for r in results if r["test_name"] == "connection_check"]
    assert len(ping_result) == 1
    assert ping_result[0]["status"] == "error"


@patch("websec_test.mongodb_check.run_mongosh_eval")
def test_anonymous_access_allowed(mock_eval):
    """Anonymous access detected when listDatabases succeeds."""
    def side_effect(uri, cmd, timeout=5, mongosh_path=None):
        if "listDatabases" in cmd:
            return {"ok": 1, "databases": [{"name": "admin"}, {"name": "local"}]}
        return {"ok": 1}
    mock_eval.side_effect = side_effect
    results = run_all_checks("mongodb://localhost:27017", mongosh_path="mongosh")
    anon_result = [r for r in results if r["test_name"] == "anonymous_access"]
    assert len(anon_result) == 1
    assert anon_result[0]["status"] == "fail"


@patch("websec_test.mongodb_check.run_mongosh_eval")
def test_anonymous_access_blocked(mock_eval):
    """Anonymous access is blocked when listDatabases raises error."""
    def side_effect(uri, cmd, timeout=5, mongosh_path=None):
        if "listDatabases" in cmd:
            raise subprocess.CalledProcessError(1, [], stderr="not authorized")
        return {"ok": 1}
    mock_eval.side_effect = side_effect
    results = run_all_checks("mongodb://localhost:27017", mongosh_path="mongosh")
    anon_result = [r for r in results if r["test_name"] == "anonymous_access"]
    assert anon_result[0]["status"] == "pass"


@patch("websec_test.mongodb_check.run_mongosh_eval")
def test_default_creds_found(mock_eval):
    """Default credentials detected when one credential pair works."""
    call_count = [0]

    def side_effect(uri, cmd, timeout=5, mongosh_path=None):
        call_count[0] += 1
        # After 2 normal calls, the 3rd call uses admin:admin URI → succeed
        if "admin:admin@" in uri:
            return {"ok": 1}
        if "listDatabases" in cmd:
            return {"ok": 1, "databases": []}
        return {"ok": 1}
    mock_eval.side_effect = side_effect
    results = run_all_checks("mongodb://localhost:27017", mongosh_path="mongosh")
    cred_result = [r for r in results if r["test_name"] == "default_credentials"]
    assert len(cred_result) == 1
    assert cred_result[0]["status"] == "fail"


@patch("websec_test.mongodb_check.run_mongosh_eval")
def test_default_creds_rejected(mock_eval):
    """No default credentials accepted → pass."""
    def side_effect(uri, cmd, timeout=5, mongosh_path=None):
        # Any URI with credentials fails
        if "://" in uri and "@" in uri:
            raise subprocess.CalledProcessError(1, [], stderr="Authentication failed")
        if "listDatabases" in cmd:
            return {"ok": 1, "databases": []}
        return {"ok": 1}
    mock_eval.side_effect = side_effect
    results = run_all_checks("mongodb://localhost:27017", mongosh_path="mongosh")
    cred_result = [r for r in results if r["test_name"] == "default_credentials"]
    assert cred_result[0]["status"] == "pass"


@patch("websec_test.mongodb_check.run_mongosh_eval")
def test_admin_users_detected(mock_eval):
    """Admin users found → warn."""
    def side_effect(uri, cmd, timeout=5, mongosh_path=None):
        if "system.users.find" in cmd:
            return [{"user": "admin", "db": "admin"}, {"user": "root", "db": "admin"}]
        return {"ok": 1}
    mock_eval.side_effect = side_effect
    results = run_all_checks("mongodb://localhost:27017", mongosh_path="mongosh")
    user_result = [r for r in results if r["test_name"] == "admin_users"]
    assert user_result[0]["status"] == "warn"


@patch("websec_test.mongodb_check.run_mongosh_eval")
def test_admin_users_empty(mock_eval):
    """No admin users → pass."""
    def side_effect(uri, cmd, timeout=5, mongosh_path=None):
        if "system.users.find" in cmd:
            return []
        return {"ok": 1}
    mock_eval.side_effect = side_effect
    results = run_all_checks("mongodb://localhost:27017", mongosh_path="mongosh")
    user_result = [r for r in results if r["test_name"] == "admin_users"]
    assert user_result[0]["status"] == "pass"


@patch("websec_test.mongodb_check.run_mongosh_eval")
def test_all_six_checks_returned(mock_eval):
    """run_all_checks returns exactly 6 results."""
    mock_eval.return_value = {"ok": 1}
    results = run_all_checks("mongodb://localhost:27017", mongosh_path="mongosh")
    assert len(results) == 6
    test_names = [r["test_name"] for r in results]
    assert "connection_check" in test_names
    assert "auth_status" in test_names
    assert "anonymous_access" in test_names
    assert "database_enumeration" in test_names
    assert "default_credentials" in test_names
    assert "admin_users" in test_names
