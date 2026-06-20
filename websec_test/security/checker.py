"""Compliance checker — verifies project against SOC 2, PCI-DSS, HIPAA, GDPR.

Each framework has a list of controls. Each control has one or more evidence
checks that look for indicators in the codebase (imports, configs, patterns).
Scoring: each control passed = 1 point toward the framework total.
"""

import os
import re
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class ControlResult:
    control_id: str
    name: str
    passed: bool
    evidence: str


@dataclass
class FrameworkResult:
    framework: str
    controls: List[ControlResult]
    score_pct: float  # 0-100

    @property
    def total(self) -> int:
        return len(self.controls)

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.controls if c.passed)


@dataclass
class ComplianceResult:
    frameworks: List[FrameworkResult]

    @property
    def overall_score(self) -> float:
        if not self.frameworks:
            return 0.0
        return sum(f.score_pct for f in self.frameworks) / len(self.frameworks)

    @property
    def worst_framework(self) -> str:
        if not self.frameworks:
            return "none"
        return min(self.frameworks, key=lambda f: f.score_pct).framework


class ComplianceChecker:
    """Check project compliance against security frameworks."""

    # Each control: (id, name, indicator patterns to search for)
    FRAMEWORKS = {
        "soc2": [
            ("CC6.1", "Logical access controls",
             [r"\bbcrypt\b", r"\bargon2\b", r"(?i)password.*hash", r"\.env\b",
              r"os\.environ", r"(?i)secret.*manager|vault"]),
            ("CC6.2", "Authentication & MFA",
             [r"(?i)mfa|2fa|two.?factor", r"authenticator", r"(?i)login.*rate.*limit"]),
            ("CC6.6", "Encryption in transit",
             [r"Strict-Transport-Security", r"TLS", r"https://", r"SSLContext",
              r"ssl\.wrap_socket"]),
            ("CC7.1", "Monitoring & logging",
             [r"logging\.", r"structlog", r"(?i)audit.*log", r"syslog"]),
            ("CC7.2", "Incident response",
             [r"(?i)incident.*response", r"(?i)security.*incident"]),
            ("CC8.1", "Change management / CI/CD",
             [r"\.github/workflows", r"Jenkinsfile", r"\.gitlab-ci", r"circleci",
              r"(?i)ci.*cd"]),
        ],
        "pci_dss": [
            ("Req3.4", "Encryption at rest",
             [r"\bcryptography\b", r"\bAES\b", r"\bFernet\b", r"encrypt", r"decrypt"]),
            ("Req4.1", "Encryption in transit (TLS 1.2+)",
             [r"Strict-Transport-Security", r"TLS", r"https://", r"SSLContext",
              r"ssl\.wrap_socket"]),
            ("Req6.5", "Secure coding / input validation",
             [r"(?i)parameterized.*query|prepared.*statement", r"sanitize",
              r"DOMPurify", r"textContent"]),
            ("Req7.1", "Least privilege / access control",
             [r"(?i)role.*based|rbac", r"(?i)permission", r"(?i)authorize"]),
            ("Req8.3", "Strong authentication (MFA)",
             [r"(?i)mfa|2fa|two.?factor", r"(?i)totp|hotp"]),
            ("Req8.4", "Password hashing",
             [r"\bbcrypt\b", r"\bargon2\b", r"salt"]),
            ("Req10.1", "Audit trails for access",
             [r"logging\.", r"(?i)audit.*log", r"(?i)access.*log"]),
        ],
        "hipaa": [
            ("164.312(a)(1)", "Unique user identification",
             [r"(?i)login|authenticate|user.*id"]),
            ("164.312(b)", "Audit controls",
             [r"logging\.", r"(?i)audit.*log", r"syslog"]),
            ("164.312(c)(1)", "Integrity controls",
             [r"(?i)checksum|hash|sha|md5|integrity"]),
            ("164.312(d)", "Person/entity authentication (MFA)",
             [r"(?i)mfa|2fa|two.?factor|totp"]),
            ("164.312(e)(1)", "Transmission security (TLS)",
             [r"Strict-Transport-Security", r"TLS", r"https://", r"SSLContext"]),
            ("164.310(a)(2)(iii)", "Workstation security / access control",
             [r"(?i)role.*based|rbac", r"(?i)permission"]),
        ],
        "gdpr": [
            ("Art.5(1)(c)", "Data minimization",
             [r"(?i)pseudonymize|anonymize|minimize"]),
            ("Art.17", "Right to erasure",
             [r"(?i)delete.*user|remove.*account|erasure|right.*to.*be.*forgotten"]),
            ("Art.20", "Data portability",
             [r"(?i)export.*data|portability|download.*data"]),
            ("Art.25", "Privacy by design / encryption",
             [r"\bcryptography\b", r"\bAES\b", r"\bFernet\b", r"encrypt"]),
            ("Art.32", "Security of processing",
             [r"(?i)pseudonymize|anonymize", r"\bbcript\b", r"\bargon2\b",
              r"Strict-Transport-Security"]),
            ("Art.33", "Breach notification",
             [r"(?i)breach.*notif|incident.*response"]),
        ],
    }

    def __init__(self, target: str):
        self.target = target

    def check(self, framework_filter: str = "all") -> ComplianceResult:
        """Run compliance checks against specified frameworks."""
        results: List[FrameworkResult] = []
        for fw_name, controls in self.FRAMEWORKS.items():
            if framework_filter not in ("all", fw_name):
                continue
            control_results = []
            for ctrl_id, ctrl_name, indicators in controls:
                passed = self._check_evidence(indicators)
                evidence = self._gather_evidence(indicators)
                control_results.append(ControlResult(
                    control_id=ctrl_id,
                    name=ctrl_name,
                    passed=passed,
                    evidence=evidence,
                ))
            total = len(control_results)
            passed = sum(1 for c in control_results if c.passed)
            score = (passed / total * 100) if total > 0 else 0
            results.append(FrameworkResult(
                framework=fw_name,
                controls=control_results,
                score_pct=score,
            ))
        return ComplianceResult(frameworks=results)

    def _check_evidence(self, indicators: List[str]) -> bool:
        """Return True if at least one indicator is found in the project."""
        if not os.path.isdir(self.target):
            return False
        try:
            for root, _dirs, files in os.walk(self.target):
                # Skip node_modules, venv, .git, __pycache__
                skip_dirs = {"node_modules", "venv", ".git", "__pycache__", ".pytest_cache"}
                if any(s in root for s in skip_dirs):
                    continue
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in (".py", ".js", ".ts", ".go", ".java", ".yaml", ".yml",
                                   ".json", ".toml", ".cfg", ".ini", ".env", ".sh", ".md"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                        for indicator in indicators:
                            if re.search(indicator, content):
                                return True
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass
        return False

    def _gather_evidence(self, indicators: List[str]) -> str:
        """Return a short evidence string from the first match found."""
        if not os.path.isdir(self.target):
            return "No matches found"
        try:
            for root, _dirs, files in os.walk(self.target):
                skip_dirs = {"node_modules", "venv", ".git", "__pycache__", ".pytest_cache"}
                if any(s in root for s in skip_dirs):
                    continue
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in (".py", ".js", ".ts", ".go", ".java", ".yaml", ".yml",
                                   ".json", ".toml", ".cfg", ".ini", ".sh", ".md"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            lines = f.readlines()
                        for lineno, line in enumerate(lines, 1):
                            for indicator in indicators:
                                if re.search(indicator, line):
                                    rel_path = os.path.relpath(fpath, self.target)
                                    snippet = line.strip()[:80]
                                    return f"{rel_path}:{lineno}: {snippet}"
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass
        return "No evidence found"

    @staticmethod
    def exit_code(result: ComplianceResult) -> int:
        """0 = compliant (90%+), 1 = non-compliant (50-89%), 2 = critical gaps (<50%)."""
        overall = result.overall_score
        if overall >= 90:
            return 0
        if overall >= 50:
            return 1
        return 2
