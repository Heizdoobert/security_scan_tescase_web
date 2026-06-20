"""Secret scanner — detect secrets, API keys, tokens, and private keys in source code.

Detection methods:
  1. Pattern matching — regex for known secret formats (AWS, GitHub, Stripe, JWT, PEM, etc.)
  2. Entropy detection — Shannon entropy on high-entropy strings (base64, hex)
  3. Git history scan — scan git log for committed secrets

No external dependencies beyond Python stdlib.
"""

import math
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


# ── Known secret patterns ──

# Each entry: (name, regex, severity, recommendation)
SECRET_PATTERNS: List[tuple] = [
    # Cloud provider keys
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "critical",
     "Rotate the AWS key immediately. Use IAM roles instead of long-lived keys."),
    ("AWS Secret Access Key", r"(?i)aws(.{0,20})?(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/=])", "critical",
     "Rotate the AWS secret key. Use IAM roles or Secrets Manager."),
    ("GCP Service Account Key", r"-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\n+/=]+-----END PRIVATE KEY-----", "critical",
     "Rotate the GCP service account key. Use workload identity federation instead."),
    ("Azure Storage Key", r"(?i)AccountKey=[a-zA-Z0-9+/]{80,}==", "critical",
     "Rotate the Azure storage key. Use managed identities or SAS tokens."),

    # API tokens
    ("GitHub Personal Access Token", r"(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", "critical",
     "Revoke the token in GitHub settings. Use GitHub Actions OIDC tokens instead."),
    ("GitLab Personal Access Token", r"(?i)glpat-[A-Za-z0-9\-_]{20,}", "critical",
     "Revoke the token in GitLab settings. Use CI/CD job tokens instead."),
    ("Slack Bot Token", r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "critical",
     "Revoke the Slack token. Use Slack app-level tokens with granular scopes."),
    ("Stripe Live API Key", r"(?i)(sk_live|pk_live)_[0-9a-zA-Z]{24,}", "critical",
     "Rotate the Stripe key immediately. Use restricted keys or Stripe Connect."),
    ("Stripe Test API Key", r"(?i)(sk_test|pk_test)_[0-9a-zA-Z]{24,}", "high",
     "Rotate the test key. Do not commit test keys to version control."),
    ("Twilio API Key", r"(?i)SK[0-9a-fA-F]{32}", "critical",
     "Rotate the Twilio key. Use Twilio Functions or environment variables."),

    # Tokens and authentication
    ("JWT Token", r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "high",
     "Do not commit JWT tokens. Use short-lived tokens or OIDC."),
    ("Bearer Token in Code", r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}", "high",
     "Remove hardcoded bearer tokens. Use environment variables or a secret manager."),
    ("Heroku API Key", r"(?i)heroku.{0,10}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "critical",
     "Rotate the Heroku key. Use Heroku OAuth tokens for CI."),

    # Private keys and certificates
    ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "critical",
     "Remove the private key from the repository. Use a secrets manager."),
    ("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "critical",
     "Remove the private key. Use hardware security modules or vault."),
    ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "critical",
     "Remove the private key from the repository. Use a secrets manager."),
    ("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "critical",
     "Remove the SSH key. Use SSH agent forwarding or short-lived certificates."),
    ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "critical",
     "Remove the PGP key. Use a hardware token or keyserver."),

    # Connection strings and databases
    ("MongoDB Connection String", r"mongodb(?:\+srv)?://[^\s]+:[^\s]+@", "critical",
     "Rotate the database credentials. Use environment variables or a vault."),
    ("PostgreSQL Connection String", r"postgres(?:ql)?://[^\s]+:[^\s]+@", "critical",
     "Rotate the database credentials. Use IAM database authentication if available."),
    ("MySQL Connection String", r"mysql://[^\s]+:[^\s]+@", "critical",
     "Rotate the database credentials. Use TLS and IAM-based authentication."),
    ("Redis Connection String", r"redis://[^\s]*:[^\s]+@", "high",
     "Rotate the Redis password. Use TLS and password-less auth on trusted networks."),
    ("Generic Database URL", r"(?i)(db_url|database_url)\s*=\s*['\"][^\s]+:[^\s]+@", "high",
     "Remove database URLs from code. Store in environment variables."),

    # Password and credential patterns
    ("Hardcoded Password Assignment", r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]", "high",
     "Remove hardcoded passwords. Use environment variables or a secret manager."),
    ("Secret Key / API Key Generic", r"(?i)(api_key|api_secret|secret_key)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "high",
     "Rotate the key immediately. Use a secrets management service."),
]

# Entropy detection thresholds
HIGH_ENTROPY_THRESHOLD = 4.5  # Shannon bits per character
MIN_ENTROPY_STRING_LENGTH = 20
MAX_ENTROPY_STRING_LENGTH = 120

# Patterns to exclude from entropy detection (common code constructs)
ENTROPY_EXCLUDE_PATTERNS = [
    r"^[a-zA-Z0-9_\s]+$",       # identifiers, comments
    r"^import\s",                # import statements
    r"^from\s",                  # from imports
    r"^#.*$",                    # comments (single line)
    r"^\s*//.*$",                # JS comments
    r"^\s*<!--",                 # HTML comments
    r"^\s*[*]",                  # block comment continuations
    r"^\s*$",                    # blank lines
    r"^[\s]*[`~\"]{3}",          # code fences
]


@dataclass
class SecretFinding:
    """A detected secret or credential in source code."""
    path: str
    line_number: int
    secret_type: str
    match_preview: str
    severity: str   # "critical" | "high" | "medium" | "low"
    context: str
    recommendation: str
    entropy: float = 0.0
    source: str = "pattern"  # "pattern" | "entropy" | "git-history"


@dataclass
class SecretScanResult:
    """Aggregated result of a secret scan."""
    target: str
    secrets: List[SecretFinding]
    files_scanned: int = 0
    git_commits_scanned: int = 0

    @property
    def count(self) -> int:
        return len(self.secrets)

    @property
    def critical_count(self) -> int:
        return sum(1 for s in self.secrets if s.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for s in self.secrets if s.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for s in self.secrets if s.severity == "medium")


class SecretScanner:
    """Scan source code for secrets, credentials, and sensitive data."""

    # Files/dirs to skip
    DEFAULT_EXCLUDE: Set[str] = {
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        ".tox", ".eggs", "*.pyc", "*.pyo", ".DS_Store",
        "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico",
        "*.woff", "*.woff2", "*.ttf", "*.eot",
        "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx",
        # Skip self (regex patterns in library are not real secrets)
        "secret_scanner.py",
    }

    # Binary file extensions to skip
    BINARY_EXTENSIONS: Set[str] = {
        ".pyc", ".pyo", ".png", ".jpg", ".jpeg", ".gif", ".ico",
        ".woff", ".woff2", ".ttf", ".eot",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip",
        ".tar", ".gz", ".bz2", ".7z", ".rar",
        ".o", ".so", ".dll", ".dylib", ".exe",
    }

    def __init__(
        self,
        min_entropy: float = HIGH_ENTROPY_THRESHOLD,
        exclude: Optional[List[str]] = None,
        severity_filter: Optional[str] = None,
    ):
        self.min_entropy = min_entropy
        self.exclude = set(self.DEFAULT_EXCLUDE)
        if exclude:
            self.exclude.update(exclude)
        self.severity_filter = severity_filter

    def _should_skip(self, path: str) -> bool:
        """Check whether a file should be skipped."""
        basename = os.path.basename(path)
        if basename in self.exclude:
            return True
        for pattern in self.exclude:
            if pattern.startswith("*") and basename.endswith(pattern[1:]):
                return True
        _, ext = os.path.splitext(path)
        return ext.lower() in self.BINARY_EXTENSIONS

    def _get_context(self, text: str, line_num: int, window: int = 2) -> str:
        """Extract surrounding context lines."""
        lines = text.splitlines()
        start = max(0, line_num - 1 - window)
        end = min(len(lines), line_num + window)
        ctx_lines = []
        for i in range(start, end):
            prefix = ">" if i == line_num - 1 else " "
            ctx_lines.append(f"{prefix} {lines[i]}")
        return "\n".join(ctx_lines)

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Compute Shannon entropy in bits per character."""
        if not s:
            return 0.0
        s = s.strip()
        if len(s) < 2:
            return 0.0
        freq = Counter(s)
        entropy = -sum(
            (count / len(s)) * math.log2(count / len(s))
            for count in freq.values()
        )
        return round(entropy, 2)

    def _is_high_entropy_string(self, s: str) -> bool:
        """Check if a string has high Shannon entropy (potential secret)."""
        entropy = self._shannon_entropy(s)
        return entropy >= self.min_entropy

    def _check_entropy(self, text: str, path: str) -> List[SecretFinding]:
        """Detect high-entropy strings that may be secrets."""
        findings: List[SecretFinding] = []
        lines = text.splitlines()

        for line_num, line in enumerate(lines, 1):
            # Skip excluded patterns
            if any(re.match(pat, line) for pat in ENTROPY_EXCLUDE_PATTERNS):
                continue

            # Find potential high-entropy tokens
            tokens = re.findall(
                rf"[A-Za-z0-9+/=_\-]{{{MIN_ENTROPY_STRING_LENGTH},{MAX_ENTROPY_STRING_LENGTH}}}",
                line,
            )
            for token in tokens:
                # Skip purely numeric or simple patterns
                if re.match(r"^\d+$", token):
                    continue
                if re.match(r"^[a-zA-Z]+$", token):
                    continue
                if token.strip(" \t") == "":
                    continue
                if self._is_high_entropy_string(token):
                    context = self._get_context(text, line_num)
                    findings.append(SecretFinding(
                        path=path,
                        line_number=line_num,
                        secret_type="High-Entropy String",
                        match_preview=token[:60] + ("..." if len(token) > 60 else ""),
                        severity="medium",
                        context=context,
                        recommendation="Verify this isn't a secret. If it is, rotate it and use env variables.",
                        entropy=round(self._shannon_entropy(token), 2),
                        source="entropy",
                    ))

        return findings

    def scan_file(self, path: str) -> List[SecretFinding]:
        """Scan a single file for secrets using pattern matching + entropy."""
        findings: List[SecretFinding] = []

        if self._should_skip(path):
            return findings

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except (IOError, UnicodeDecodeError):
            return findings

        # Pattern matching
        for name, pattern, severity, recommendation in SECRET_PATTERNS:
            for match in re.finditer(pattern, text):
                line_num = text[:match.start()].count("\n") + 1
                context = self._get_context(text, line_num)
                preview = match.group()[:60]

                finding = SecretFinding(
                    path=path,
                    line_number=line_num,
                    secret_type=name,
                    match_preview=preview + ("..." if len(match.group()) > 60 else ""),
                    severity=severity,
                    context=context,
                    recommendation=recommendation,
                )
                findings.append(finding)

        # Entropy detection
        entropy_findings = self._check_entropy(text, path)
        findings.extend(entropy_findings)

        return findings

    def scan_directory(
        self,
        target: str,
    ) -> SecretScanResult:
        """Recursively scan a directory for secrets."""
        all_secrets: List[SecretFinding] = []
        scanned: List[str] = []

        for root, dirs, files in os.walk(target):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.exclude]

            for fname in files:
                fpath = os.path.join(root, fname)
                if self._should_skip(fpath):
                    continue
                scanned.append(fpath)
                try:
                    secrets = self.scan_file(fpath)
                    all_secrets.extend(secrets)
                except Exception:
                    continue

        result = SecretScanResult(
            target=target,
            secrets=all_secrets,
            files_scanned=len(scanned),
        )

        if self.severity_filter:
            self._apply_severity_filter(result)

        return result

    def scan_git_history(self, target: str, max_commits: int = 100) -> Tuple[List[SecretFinding], int]:
        """Scan git history for secrets added in past commits.

        Returns (findings, commits_scanned).
        """
        findings: List[SecretFinding] = []

        try:
            result = subprocess.run(
                ["git", "log", "-p", f"--max-count={max_commits}"],
                capture_output=True, text=True, timeout=30,
                cwd=target,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return findings, 0

        if result.returncode != 0:
            return findings, 0

        output = result.stdout
        commits_scanned = len(re.findall(r"^commit\s([a-f0-9]+)", output, re.MULTILINE))
        current_commit = ""
        for name, pattern, severity, recommendation in SECRET_PATTERNS:
            for match in re.finditer(pattern, output):
                # Find surrounding commit hash
                text_before = output[:match.start()]
                commit_match = re.findall(r"commit\s([a-f0-9]+)", text_before)
                current_commit = commit_match[-1] if commit_match else "unknown"

                # Find line number within git diff
                line_match = re.findall(r"^@@ -\d+,\d+ \+(\d+),\d+ @@", text_before, re.MULTILINE)
                line_num = int(line_match[-1]) if line_match else 0

                finding = SecretFinding(
                    path=f"git:{current_commit[:8]}",
                    line_number=line_num,
                    secret_type=name,
                    match_preview=match.group()[:60],
                    severity=severity,
                    context=f"Commit {current_commit[:8]}",
                    recommendation=f"{recommendation} Also remove the secret from git history using git-filter-repo.",
                    source="git-history",
                )
                findings.append(finding)

        return findings

    def scan_all(
        self,
        target: str,
        git_history: bool = False,
    ) -> SecretScanResult:
        """Run full secret scan: directory scan + optional git history."""
        all_secrets: List[SecretFinding] = []
        git_commits = 0

        result = self.scan_directory(target)
        all_secrets.extend(result.secrets)
        files_scanned = result.files_scanned

        if git_history:
            git_findings, git_commits = self.scan_git_history(target)
            all_secrets.extend(git_findings)

        return SecretScanResult(
            target=target,
            secrets=all_secrets,
            files_scanned=files_scanned,
            git_commits_scanned=git_commits,
        )

    def _apply_severity_filter(self, result: SecretScanResult) -> None:
        """Filter secrets by minimum severity level."""
        severity_order = ["low", "medium", "high", "critical"]
        try:
            min_idx = severity_order.index(self.severity_filter)
        except ValueError:
            return
        result.secrets = [
            s for s in result.secrets
            if severity_order.index(s.severity) >= min_idx
        ]

    @staticmethod
    def exit_code(result: SecretScanResult) -> int:
        """Determine exit code from scan result."""
        if result.critical_count > 0:
            return 2
        if result.high_count > 0:
            return 1
        return 0


# Self-test when run directly
if __name__ == "__main__":
    scanner = SecretScanner()
    result = scanner.scan_all(".", git_history=True)
    print(f"Files scanned: {result.files_scanned}")
    print(f"Git commits scanned: {result.git_commits_scanned}")
    print(f"Secrets found: {result.count}")
    print(f"  Critical: {result.critical_count}")
    print(f"  High: {result.high_count}")
    print(f"  Medium: {result.medium_count}")
    for s in result.secrets:
        print(f"  [{s.severity.upper()}] {s.secret_type}: {s.path}:{s.line_number}")
    sys.exit(SecretScanner.exit_code(result))
