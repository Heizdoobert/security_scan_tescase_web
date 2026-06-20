"""SAST security scanner — pattern-matches source code for vulnerabilities.

No external dependencies. Scans by file extension with regex patterns.
Detects: hardcoded secrets, SQL injection, XSS, command injection, path traversal.
"""

import os
import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    file_path: str
    line_number: int
    category: str
    severity: str         # "critical" | "high" | "medium" | "low"
    evidence: str
    recommendation: str


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class SecurityScanner:
    """Scans source files for common vulnerability patterns."""

    EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php"}
    SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv", "env", ".env",
                 ".pytest_cache", ".eggs", "dist", "build", ".svn", ".hg", ".idea", ".vscode"}

    PATTERNS = [
        # ── Hardcoded secrets ──
        {
            "category": "hardcoded_api_key",
            "severity": "critical",
            "pattern": re.compile(
                r'(?:api[_-]?key|apikey|secret|token)\s*[=:]\s*["\']'
                r'(?:sk-[A-Za-z0-9]{20,}|[A-Za-z0-9+/]{20,}={0,2})["\']',
                re.IGNORECASE,
            ),
            "recommendation": "Move to environment variable or secrets manager",
        },
        {
            "category": "aws_credential",
            "severity": "critical",
            "pattern": re.compile(
                r'(?:AKIA[0-9A-Z]{16}|(?:aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']'
                r'[A-Za-z0-9/+=]{20,})',
            ),
            "recommendation": "Rotate credential immediately, use IAM roles or env vars",
        },
        {
            "category": "private_key",
            "severity": "critical",
            "pattern": re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
            "recommendation": "Store private keys in a secrets manager, never in source",
        },
        {
            "category": "github_token",
            "severity": "critical",
            "pattern": re.compile(
                r'(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}',
            ),
            "recommendation": "Revoke token, use GitHub Actions secrets or env vars",
        },
        {
            "category": "jwt_token",
            "severity": "high",
            "pattern": re.compile(
                r'(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})',
            ),
            "recommendation": "Do not hardcode JWTs; issue at runtime via identity provider",
        },

        {
            "category": "hardcoded_password",
            "severity": "high",
            "pattern": re.compile(
                r'(?:password|pwd|passwd)\s*[=:]\s*["\'][^"\']{3,}["\']',
                re.IGNORECASE,
            ),
            "recommendation": "Move credentials to environment variables or a secrets manager",
        },

        # ── SQL injection ──
        {
            "category": "sql_injection",
            "severity": "critical",
            "pattern": re.compile(
                r'(?:cursor\.execute|db\.execute|db\.query|session\.execute)\s*\(?\s*f["\']',
            ),
            "recommendation": "Use parameterized queries instead of f-strings or concatenation",
        },
        {
            "category": "sql_injection_concat",
            "severity": "high",
            "pattern": re.compile(
                r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.+["\']\s*[+%]\s*\w+\s*'
                r'(?:$|["\'])',
                re.IGNORECASE,
            ),
            "recommendation": "Use parameterized queries with placeholders",
        },

        # ── XSS ──
        {
            "category": "xss_inner_html",
            "severity": "high",
            "pattern": re.compile(r'\.innerHTML\s*='),
            "recommendation": "Use textContent instead of innerHTML, or sanitize with DOMPurify",
        },
        {
            "category": "xss_dangerous_react",
            "severity": "high",
            "pattern": re.compile(r'dangerouslySetInnerHTML'),
            "recommendation": "Avoid dangerouslySetInnerHTML; use React components that escape by default",
        },
        {
            "category": "xss_dom_api",
            "severity": "medium",
            "pattern": re.compile(
                r'(?:document\.write|eval\(|setTimeout\s*\(|setInterval\s*\()\s*["\']?.*\b(?:location|hash|search)\b',
            ),
            "recommendation": "Avoid writing unescaped user input to the DOM",
        },

        # ── Command injection ──
        {
            "category": "command_injection_shell",
            "severity": "critical",
            "pattern": re.compile(r'shell\s*=\s*True'),
            "recommendation": "Avoid shell=True; use subprocess.run with a list of args",
        },
        {
            "category": "command_injection_os_system",
            "severity": "high",
            "pattern": re.compile(r'os\.system\s*\([^)]*\b(?:input|request|get|post|data)\b'),
            "recommendation": "Use subprocess.run with a list instead of os.system",
        },
        {
            "category": "command_injection_eval",
            "severity": "critical",
            "pattern": re.compile(r'(?:eval|exec)\s*\([^)]*\b(?:input|request|get|data)\b'),
            "recommendation": "Avoid eval/exec with user input; use safe parsers",
        },

        # ── Path traversal ──
        {
            "category": "path_traversal_open",
            "severity": "high",
            "pattern": re.compile(
                r'(?:open|open\(|Path\(|path\.join)\s*\([^)]*\b(?:input|filename|path|file|name)\b',
            ),
            "recommendation": "Validate and sanitize user-supplied file paths; use allowlist",
        },

        # ── Weak crypto (MD5 / SHA1) ──
        {
            "category": "weak_crypto",
            "severity": "medium",
            "pattern": re.compile(r'(?:hashlib\.md5|hashlib\.sha1|Crypt\|MD5|MessageDigest\(.*MD5)'),
            "recommendation": "Use SHA-256 or stronger hashing; avoid MD5 and SHA-1",
        },

        # ── Insecure deserialization ──
        {
            "category": "insecure_deserialization",
            "severity": "high",
            "pattern": re.compile(
                r'(?:pickle\.loads|pickle\.load|yaml\.load\s*\(|PyYAML\.load|marshal\.loads?'
                r'|CSerializer\.deserialize)',
            ),
            "recommendation": "Avoid pickle/yaml.load with untrusted data; use safe parsers",
        },

        # ── OS command injection (generic) ──
        {
            "category": "os_command_injection",
            "severity": "critical",
            "pattern": re.compile(r'os\.system\s*\('),
            "recommendation": "Use subprocess.run with a list of args instead of os.system",
        },
    ]

    def __init__(self, target: str, min_severity: str = "low"):
        self.target = target
        self.min_severity = min_severity
        self.min_order = SEVERITY_ORDER.get(min_severity, 3)

    def scan(self) -> List[Finding]:
        """Scan the target path and return all findings."""
        findings: List[Finding] = []
        if not os.path.exists(self.target):
            return findings

        if os.path.isfile(self.target):
            self._scan_file(self.target, findings)
        else:
            for root, dirs, files in os.walk(self.target):
                # Prune ignored directories in-place so os.walk skips them
                dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in self.EXTENSIONS:
                        self._scan_file(os.path.join(root, fname), findings)

        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file_path))
        return findings

    def _scan_file(self, file_path: str, findings: List[Finding]):
        """Scan a single file against all patterns."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            return

        for lineno, line in enumerate(lines, 1):
            stripped = line.rstrip("\n")
            for rule in self.PATTERNS:
                if SEVERITY_ORDER.get(rule["severity"], 9) > self.min_order:
                    continue
                if rule["pattern"].search(stripped):
                    findings.append(Finding(
                        file_path=os.path.relpath(file_path, self.target)
                        if os.path.isdir(self.target) else file_path,
                        line_number=lineno,
                        category=rule["category"],
                        severity=rule["severity"],
                        evidence=stripped.strip()[:120],
                        recommendation=rule["recommendation"],
                    ))

    def has_critical(self, findings: List[Finding]) -> bool:
        return any(f.severity == "critical" for f in findings)

    def has_high(self, findings: List[Finding]) -> bool:
        return any(f.severity == "high" for f in findings)

    @staticmethod
    def exit_code(findings: List[Finding]) -> int:
        """0 = clean, 1 = high findings, 2 = critical findings."""
        if any(f.severity == "critical" for f in findings):
            return 2
        if any(f.severity == "high" for f in findings):
            return 1
        return 0
