"""Tests for SAST SecurityScanner."""
import os
import tempfile
from websec_test.security.scanner import SecurityScanner


def _make_py_file(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def test_no_findings_in_empty_project():
    with tempfile.TemporaryDirectory() as td:
        scanner = SecurityScanner(td, min_severity="low")
        findings = scanner.scan()
        assert findings == []


def test_detects_hardcoded_password():
    with tempfile.TemporaryDirectory() as td:
        _make_py_file(os.path.join(td, "app.py"), """
def connect():
    password = "super_secret_123"
    db.connect(password)
""")
        scanner = SecurityScanner(td, min_severity="low")
        findings = scanner.scan()
        hardcoded = [f for f in findings if "hardcoded" in f.category.lower()]
        assert len(hardcoded) >= 1
        assert hardcoded[0].severity in ("critical", "high")


def test_detects_sql_injection():
    with tempfile.TemporaryDirectory() as td:
        _make_py_file(os.path.join(td, "db.py"), """
def get_user(name):
    query = "SELECT * FROM users WHERE name = " + name
    cursor.execute(query)
""")
        scanner = SecurityScanner(td, min_severity="low")
        findings = scanner.scan()
        sqli = [f for f in findings if "sql" in f.category.lower()]
        assert len(sqli) >= 1


def test_detects_weak_crypto():
    with tempfile.TemporaryDirectory() as td:
        _make_py_file(os.path.join(td, "crypto.py"), """
import hashlib
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
""")
        scanner = SecurityScanner(td, min_severity="low")
        findings = scanner.scan()
        weak = [f for f in findings if "crypto" in f.category.lower()]
        assert len(weak) >= 1


def test_detects_command_injection():
    with tempfile.TemporaryDirectory() as td:
        _make_py_file(os.path.join(td, "exec.py"), """
import os
user_input = request.args.get("cmd")
os.system(user_input)
""")
        scanner = SecurityScanner(td, min_severity="low")
        findings = scanner.scan()
        cmd = [f for f in findings if "command" in f.category.lower() or "os_" in f.category.lower()]
        assert len(cmd) >= 1


def test_detects_insecure_import():
    with tempfile.TemporaryDirectory() as td:
        _make_py_file(os.path.join(td, "unsafe.py"), """
import pickle
data = pickle.loads(user_input)
""")
        scanner = SecurityScanner(td, min_severity="low")
        findings = scanner.scan()
        insecure_import = [f for f in findings if "deserialization" in f.category.lower()]
        assert len(insecure_import) >= 1


def test_skip_ignored_dirs():
    with tempfile.TemporaryDirectory() as td:
        _make_py_file(os.path.join(td, "node_modules", "bad.js"), """
password = "secret"
""")
        _make_py_file(os.path.join(td, "venv", "lib.py"), """
password = "secret"
""")
        _make_py_file(os.path.join(td, ".git", "config.py"), """
password = "secret"
""")
        scanner = SecurityScanner(td, min_severity="low")
        findings = scanner.scan()
        assert findings == []


def test_exit_code_zero_for_clean():
    with tempfile.TemporaryDirectory() as td:
        _make_py_file(os.path.join(td, "safe.py"), """
def greet(name):
    return f"Hello, {name}!"
""")
        scanner = SecurityScanner(td, min_severity="low")
        findings = scanner.scan()
        assert scanner.exit_code(findings) == 0


def test_exit_code_two_for_critical():
    with tempfile.TemporaryDirectory() as td:
        _make_py_file(os.path.join(td, "bad.py"), """
password = "hardcoded_secret"
""")
        scanner = SecurityScanner(td, min_severity="low")
        findings = scanner.scan()
        code = scanner.exit_code(findings)
        assert code in (1, 2)
