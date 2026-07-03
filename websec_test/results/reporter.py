"""Reporter — terminal, JSON, log output and dashboard for test results."""
import json
import webbrowser
from datetime import datetime
from pathlib import Path
from websec_test.results.collector import ResultCollector
from websec_test.results.models import TestStatus, Severity


def _msg(result, tense="pass") -> str:
    """Describe what was checked — positive for PASS, normative for FAIL/WARN."""
    name = result.test_name.lower()

    # ── Headers ──
    if "header" in result.module or name.startswith("check_"):
        h_names = {"sts": "Strict-Transport-Security", "hsts": "Strict-Transport-Security",
                    "strict_transport": "Strict-Transport-Security",
                    "content_security": "Content-Security-Policy",
                    "x_frame": "X-Frame-Options", "x_content": "X-Content-Type-Options",
                    "referrer": "Referrer-Policy", "permissions": "Permissions-Policy",
                    "cross_origin_opener": "Cross-Origin-Opener-Policy",
                    "cross_origin_resource": "Cross-Origin-Resource-Policy"}
        for key, hdr in h_names.items():
            if key in name:
                if tense == "pass":
                    return f"{hdr} header is present"
                return f"Should include the {hdr} header"

    # ── Cookies ──
    if "secure" in name:
        return "Secure flag is set on all cookies" if tense == "pass" else "Should set Secure flag on cookies"
    if "httponly" in name:
        return "HttpOnly flag is set on all cookies" if tense == "pass" else "Should set HttpOnly flag on cookies"
    if "samesite" in name:
        return "SameSite flag is set on all cookies" if tense == "pass" else "Should set SameSite flag on cookies"

    # ── CORS ──
    if "wildcard" in name:
        return "CORS does not allow wildcard origin" if tense == "pass" else "Should not allow wildcard CORS origin"
    if "credentials" in name and "wildcard" in name:
        return "CORS does not allow credentials with wildcard" if tense == "pass" else "Should not allow credentials with wildcard origin"
    if "reflected" in name:
        return "CORS origin is not reflected" if tense == "pass" else "Should not reflect CORS origin header"

    # ── Injection ──
    if "sqli" in name or "sql" in name:
        return "No SQL injection vulnerability detected" if tense == "pass" else "Should reject SQL injection payloads"
    if "xss" in name:
        return "No reflected XSS vulnerability detected" if tense == "pass" else "Should reject XSS payloads"
    if "nosql" in name or "nosqli" in name:
        return "No NoSQL injection vulnerability detected" if tense == "pass" else "Should reject NoSQL injection payloads"
    if "cmd_inject" in name or "command" in name:
        return "No command injection vulnerability detected" if tense == "pass" else "Should reject command injection payloads"

    # ── Auth ──
    if "blank_password" in name:
        return "Blank passwords are rejected" if tense == "pass" else "Should reject blank password login attempts"
    if "rate_limit" in name:
        return "Rate limiting is enforced" if tense == "pass" else "Should enforce rate limiting on auth endpoints"
    if "username_enum" in name or "enum" in name:
        return "Usernames cannot be enumerated" if tense == "pass" else "Should not reveal valid vs invalid usernames"
    if "sqli_bypass" in name or "login_bypass" in name:
        return "SQLi login bypass is blocked" if tense == "pass" else "Should block SQL injection in login forms"
    if "csrf" in name:
        return "CSRF protection is active" if tense == "pass" else "Should require and validate CSRF tokens"
    if "disable" in name or "delete" in name:
        return "Destructive actions require authorization" if tense == "pass" else "Action should be blocked for unauthorized users" if tense != "pass" else "Destructive actions require authorization"
    if "forgot" in name or "reset" in name:
        return "Password reset requires verification" if tense == "pass" else "Password reset should require email/token verification"
    if "idor" in name or "private" in name:
        return "User data is properly isolated" if tense == "pass" else "Private data should not be accessible by other users"
    if "admin" in name or "role" in name:
        return "Admin access is properly restricted" if tense == "pass" else "Admin operations should be restricted to admin role"
    if "forced_browsing" in name:
        return "Sensitive paths are protected" if tense == "pass" else "Should block access to sensitive paths"

    # ── SSL/TLS ──
    if "certificate" in name:
        return "SSL certificate is valid" if tense == "pass" else "Should have a valid SSL certificate"
    if "tls_1_0" in name or "weak_protocol" in name:
        return "TLS 1.0 is disabled" if tense == "pass" else "Should disable TLS 1.0"
    if "hsts_preload" in name:
        return "HSTS preload is ready" if tense == "pass" else "Should configure HSTS preload"

    # ── Disclosure ──
    if "server" in name:
        return "Server version banner is hidden" if tense == "pass" else "Should hide server version header"
    if "x_powered" in name:
        return "X-Powered-By header is hidden" if tense == "pass" else "Should remove X-Powered-By header"
    if "directory_listing" in name:
        return "Directory listing is disabled" if tense == "pass" else "Should disable directory listing"
    if "stack_trace" in name:
        return "Stack traces are hidden" if tense == "pass" else "Should not expose stack traces on errors"

    # ── Methods ──
    if "options" in name or "allow" in name:
        return "Only safe HTTP methods are allowed" if tense == "pass" else "Should restrict allowed HTTP methods"
    if "trace" in name:
        return "TRACE method is disabled" if tense == "pass" else "Should disable TRACE method"
    if "put" in name:
        return "PUT method is disabled" if tense == "pass" else "Should disable PUT method"
    if "delete" in name:
        return "DELETE method is disabled" if tense == "pass" else "Should disable DELETE method"
    if "verb_tamper" in name:
        return "Verb tampering is blocked" if tense == "pass" else "Should block HTTP verb tampering"

    # ── Fallback ──
    if tense == "pass":
        return f"{result.test_name}: passed"
    sev = result.severity.value if hasattr(result.severity, 'value') else str(result.severity)
    return f"Should reject or block this {sev} severity vulnerability"


def _fmt_terminal(result, label, detail) -> str:
    """Format a single result line for terminal output."""
    line = f"  [{label}] {result.module}/{result.test_name}"
    if detail:
        line += f"  \u2192  {detail[:90]}"
    else:
        line += f"\n         Check: {_msg(result, 'pass') if result.status == TestStatus.PASS else _msg(result, 'fail')}"
        line += f"\n         Result: {result.evidence[:120] if result.evidence else 'N/A'}"
        line += f"\n         Endpoint: {result.endpoint}"
        if result.recommendation:
            line += f"\n         Fix: {result.recommendation}"
    return line


class Reporter:
    """Formats test results as terminal output and JSON reports."""

    def __init__(self, collector: ResultCollector, target: str, duration: float = 0.0):
        self.collector = collector
        self.target = target
        self.duration = duration
        self._start_time = datetime.now()

    def _build_report(self) -> dict:
        return {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": self.duration,
            "start_time": self._start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "summary": {
                "total": self.collector.total,
                "pass": self.collector.by_status.get(TestStatus.PASS, 0),
                "fail": self.collector.by_status.get(TestStatus.FAIL, 0),
                "warn": self.collector.by_status.get(TestStatus.WARN, 0),
                "error": self.collector.by_status.get(TestStatus.ERROR, 0),
            },
            "results": [
                {
                    "module": r.module,
                    "test_name": r.test_name,
                    "status": r.status.value,
                    "severity": r.severity.value,
                    "endpoint": r.endpoint,
                    "expected": _msg(r, "pass" if r.status == TestStatus.PASS else "fail"),
                    "actual": r.evidence,
                    "recommendation": r.recommendation,
                    "http_log": getattr(r, 'http_log', '')
                }
                for r in self.collector.results
            ],
        }

    def to_json(self, output_dir: str) -> str:
        """Write JSON report to output_dir and return the file path."""
        path = Path(output_dir) / f"websec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self._build_report(), f, indent=2)
        return str(path)

    def to_terminal(self):
        """Print results to terminal — PASS compact one-liner, FAIL/WARN/ERROR detailed."""
        BY_STATUS = {
            TestStatus.PASS: "\033[32mPASS\033[0m",
            TestStatus.FAIL: "\033[31mFAIL\033[0m",
            TestStatus.WARN: "\033[33mWARN\033[0m",
            TestStatus.ERROR: "\033[31mERROR\033[0m",
        }
        print(f"\n{'='*60}")
        print(f"  Web Security Test — {self.target}")
        print(f"{'='*60}")
        print(f"  Start: {self._start_time.isoformat()}")
        print(f"  Modules: {len(set(r.module for r in self.collector.results))}")
        print(f"{'='*60}")
        n_pass = n_fail = n_warn = n_err = 0
        for r in self.collector.results:
            label = BY_STATUS.get(r.status, str(r.status.value))
            ev = r.evidence[:100] if r.evidence else ""
            if r.status == TestStatus.PASS:
                n_pass += 1
                print(f"  [{label}] {r.module}/{r.test_name}  ->  {_msg(r, 'pass')}: {ev}")
            else:
                if r.status == TestStatus.FAIL:
                    n_fail += 1
                elif r.status == TestStatus.WARN:
                    n_warn += 1
                else:
                    n_err += 1
                print(f"  [{label}] {r.module}/{r.test_name}")
                print(f"         Check: {_msg(r, 'fail')}")
                print(f"         Result: {ev}")
                print(f"         Endpoint: {r.endpoint}")
                if r.recommendation:
                    print(f"         Fix: {r.recommendation}")
        end_time = datetime.now()
        print(f"{'-'*60}")
        print(f"  End: {end_time.isoformat()}  |  Duration: {self.duration:.2f}s")
        print(f"  Summary: {self.collector.total} total"
              f"  |  PASS: {n_pass}  |  FAIL: {n_fail}  |  WARN: {n_warn}  |  ERROR: {n_err}")
        print(f"{'='*60}\n")

    def to_dashboard(self, output_dir: str = "./reports", open_browser: bool = False, live: bool = False) -> str:
        """Generate an HTML dashboard (3 files: .html, .css, .js) and return the file path."""
        from websec_test.results.dashboard import Dashboard

        dash = Dashboard(self)
        path = dash.render(output_dir, open_browser, live)
        return path
