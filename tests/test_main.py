"""Tests for CLI entry point."""
import sys
import tempfile
import pytest
from unittest import mock
from websec_test.main import parse_args, run, main


def test_main_requires_target_or_secops():
    """Without --target or --secops, main() should exit with error."""
    with mock.patch("sys.argv", ["websec_test.main"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1


def test_parse_args_defaults():
    args = parse_args(["--target", "http://test.local"])
    assert args.target == "http://test.local"
    assert args.auth is None
    assert args.modules is None
    assert args.output == "./reports"
    assert args.timeout == 10


def test_parse_args_all_options():
    args = parse_args([
        "--target", "http://test.local",
        "--auth", "admin:pass",
        "--modules", "headers", "auth",
        "--output", "/tmp/results",
        "--timeout", "30",
    ])
    assert args.target == "http://test.local"
    assert args.auth == "admin:pass"
    assert args.modules == ["headers", "auth"]
    assert args.output == "/tmp/results"
    assert args.timeout == 30


def test_parse_args_check_level():
    """--check-level should default to False, True when passed."""
    args = parse_args(["--target", "http://test.local"])
    assert args.check_level is False
    args = parse_args(["--target", "http://test.local", "--check-level"])
    assert args.check_level is True


def test_parse_args_all_modules():
    args = parse_args(["--target", "http://test.local", "--all"])
    expected = ["headers", "auth", "csrf", "injection", "authz",
                "ssl_tls", "cors", "cookies", "disclosure", "methods"]
    assert args.modules == expected


@mock.patch("websec_test.main.parse_args")
@mock.patch("websec_test.main.run")
def test_main_entry(mock_run, mock_parse):
    from websec_test import main
    mock_parse.return_value = mock.MagicMock(
        target="http://test.local", auth=None,
        modules=None, output="./reports", timeout=10, verbose=False,
        secops=None, log=None
    )
    assert hasattr(main, "main")


def test_parse_args_log_defaults_to_none():
    """--log not provided should store None."""
    args = parse_args(["--target", "http://test.local"])
    assert args.log is None


def test_parse_args_log_without_path():
    """--log without a path should default to 'log.txt'."""
    args = parse_args(["--target", "http://test.local", "--log"])
    assert args.log == "log.txt"


def test_parse_args_log_with_path():
    """--log /path/to/log.txt should store the path."""
    args = parse_args(["--target", "http://test.local", "--log", "custom.log"])
    assert args.log == "custom.log"


def test_parse_args_secops_defaults_to_cwd():
    """--secops without a path should default to '.'."""
    args = parse_args(["--secops"])
    assert args.secops == "."
    assert args.target is None


def test_parse_args_secops_with_path():
    """--secops /path/to/project should store the path."""
    args = parse_args(["--secops", "/tmp/myproject"])
    assert args.secops == "/tmp/myproject"
    assert args.target is None


@mock.patch("websec_test.main.run_secops")
def test_main_dispatches_to_secops(mock_run_secops):
    """When --secops is provided, main() should call run_secops()."""
    with mock.patch("sys.argv", ["websec_test.main", "--secops", "."]):
        main()
    mock_run_secops.assert_called_once()


@mock.patch("websec_test.main.run_secops")
@mock.patch("websec_test.main.run")
def test_secops_does_not_call_web_tests(mock_run, mock_run_secops):
    """--secops should bypass the normal web test pipeline."""
    with mock.patch("sys.argv", ["websec_test.main", "--secops", "."]):
        main()
    mock_run_secops.assert_called_once()
    mock_run.assert_not_called()


def test_parse_args_check():
    """--check should be None when not provided, string when provided."""
    args = parse_args(["--target", "http://test.local"])
    assert args.check is None
    args = parse_args(["--target", "http://test.local", "--check", "headers/check_strict_transport_security"])
    assert args.check == "headers/check_strict_transport_security"


@mock.patch("websec_test.main.run")
def test_parse_args_check_with_module_and_auth(mock_run):
    """--check should parse correctly with --auth."""
    with mock.patch("sys.argv", [
        "websec_test.main", "--target", "http://test.local",
        "--auth", "admin:pass", "--check", "auth/blank_password_login",
    ]):
        main()
    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args.check == "auth/blank_password_login"
    assert args.auth == "admin:pass"


# ── Discover mode tests ──────────────────────────────────────────────

def test_parse_args_discover_defaults_false():
    """--discover should default to False when not provided."""
    args = parse_args(["--target", "http://test.local"])
    assert args.discover is False


def test_parse_args_discover_true_when_passed():
    """--discover should be True when passed."""
    args = parse_args(["--target", "http://test.local", "--discover"])
    assert args.discover is True


def test_parse_args_discover_with_modules():
    """--discover should work with --modules."""
    args = parse_args(["--target", "http://test.local", "--discover",
                       "--modules", "headers", "cors"])
    assert args.discover is True
    assert args.modules == ["headers", "cors"]


@mock.patch("requests.get")
def test_run_discover_integration(mock_get):
    """run() with --discover should call run_discover and exit 0."""
    mock_get.return_value.status_code = 200

    from websec_test.main import run, parse_args
    args = parse_args(["--target", "http://test.local",
                       "--discover", "--modules", "headers"])
    with mock.patch("sys.argv", ["websec_test.main"]):
        with pytest.raises(SystemExit) as exc:
            run(args)
    assert exc.value.code == 0


@mock.patch("requests.get")
def test_run_discover_skips_test_execution(mock_get):
    """run() with --discover should NOT run any tests (blackboard should be empty)."""
    mock_get.return_value.status_code = 200

    from websec_test.main import run, parse_args
    args = parse_args(["--target", "http://test.local",
                       "--discover", "--modules", "headers"])
    with mock.patch("sys.argv", ["websec_test.main"]):
        with pytest.raises(SystemExit) as exc:
            run(args)
    assert exc.value.code == 0


@mock.patch("requests.get")
def test_run_discover_with_auth(mock_get):
    """--discover should work with --auth (auth module needs credentials)."""
    mock_get.return_value.status_code = 200

    from websec_test.main import run, parse_args
    args = parse_args(["--target", "http://test.local",
                       "--auth", "admin:pass",
                       "--discover", "--modules", "auth"])
    with mock.patch("sys.argv", ["websec_test.main"]):
        with pytest.raises(SystemExit) as exc:
            run(args)
    assert exc.value.code == 0
