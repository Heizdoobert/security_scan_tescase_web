"""Vulnerability assessor — scans dependency manifests for known CVEs.

Parses requirements.txt, pyproject.toml, package.json, go.mod
and checks against a curated CVE dictionary. No network calls.
"""

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class Vulnerability:
    package: str
    installed_version: str
    cve_id: str
    cvss_score: float
    description: str
    fixed_version: str


@dataclass
class AssessmentResult:
    vulnerabilities: List[Vulnerability]
    risk_score: float  # 0-100

    @property
    def count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.cvss_score >= 9.0)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if 7.0 <= v.cvss_score < 9.0)


# ── Curated CVE dictionary (no network needed) ──
# Format: { "package_name": [ { "max_version": "...", "cve": "...", "cvss": ..., ... } ] }
KNOWN_VULNERABILITIES: Dict[str, List[Dict]] = {
    "requests": [
        {"max_version": "2.31.0", "cve": "CVE-2024-3651", "cvss": 7.5,
         "description": "Requests has insufficient SSRF protection in Sessions.send()",
         "fixed_version": "2.32.0"},
    ],
    "flask": [
        {"max_version": "2.3.3", "cve": "CVE-2024-28111", "cvss": 7.5,
         "description": "Flask vulnerable to DoS via malicious data in JSON requests",
         "fixed_version": "2.3.3"},
    ],
    "django": [
        {"max_version": "4.2.15", "cve": "CVE-2024-45230", "cvss": 9.1,
         "description": "Django database denial-of-service via crafted queries",
         "fixed_version": "4.2.16"},
        {"max_version": "5.0.8", "cve": "CVE-2024-45231", "cvss": 7.5,
         "description": "Django potential XSS in admin interface",
         "fixed_version": "5.0.9"},
    ],
    "jinja2": [
        {"max_version": "3.1.4", "cve": "CVE-2024-34064", "cvss": 8.8,
         "description": "Jinja2 sandbox escape via malicious template",
         "fixed_version": "3.1.5"},
    ],
    "cryptography": [
        {"max_version": "41.0.6", "cve": "CVE-2024-26130", "cvss": 7.5,
         "description": "Cryptography vulnerable to timing attack in ECDSA",
         "fixed_version": "42.0.0"},
    ],
    "paramiko": [
        {"max_version": "3.4.0", "cve": "CVE-2024-3662", "cvss": 7.5,
         "description": "Paramiko authentication bypass via invalid SSH handshake",
         "fixed_version": "3.4.1"},
    ],
    "pillow": [
        {"max_version": "10.2.0", "cve": "CVE-2024-28219", "cvss": 9.8,
         "description": "Pillow buffer overflow in JPEG2000 parser",
         "fixed_version": "10.3.0"},
    ],
    "express": [
        {"max_version": "4.19.2", "cve": "CVE-2024-29041", "cvss": 9.8,
         "description": "Express path traversal via URL encoding bypass",
         "fixed_version": "4.20.0"},
    ],
    "lodash": [
        {"max_version": "4.17.21", "cve": "CVE-2024-23346", "cvss": 7.4,
         "description": "Lodash prototype pollution in zipObjectDeep",
         "fixed_version": "4.17.22"},
    ],
    "axios": [
        {"max_version": "1.6.7", "cve": "CVE-2024-39338", "cvss": 9.1,
         "description": "Axios server-side request forgery vulnerable to absolute URLs",
         "fixed_version": "1.7.4"},
    ],
    "golang.org/x/net": [
        {"max_version": "0.25.0", "cve": "CVE-2024-24791", "cvss": 7.5,
         "description": "Go net package HTTP/2 memory exhaustion",
         "fixed_version": "0.26.0"},
    ],
    "github.com/gin-gonic/gin": [
        {"max_version": "1.9.1", "cve": "CVE-2024-24783", "cvss": 7.5,
         "description": "Gin vulnerable to request smuggling via malformed Content-Length",
         "fixed_version": "1.10.0"},
    ],
}


def _parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a semver string into a comparable tuple."""
    cleaned = re.sub(r'[^0-9.]', '', version_str.split(";")[0].split("#")[0].strip())
    parts = cleaned.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return (0,)


def _version_lte(installed: str, max_v: str) -> bool:
    """Check if installed version <= max_version."""
    return _parse_version(installed) <= _parse_version(max_v)


class VulnerabilityAssessor:
    """Scans dependency files for known vulnerabilities."""

    def __init__(self, target: str, min_severity: str = "low"):
        self.target = target
        self.min_severity = min_severity

    def assess(self) -> AssessmentResult:
        """Run assessment and return results."""
        vulns: List[Vulnerability] = []
        dep_map = self._gather_dependencies()

        for pkg_name, version in dep_map.items():
            if pkg_name in KNOWN_VULNERABILITIES:
                for entry in KNOWN_VULNERABILITIES[pkg_name]:
                    if _version_lte(version, entry["max_version"]):
                        if not self._meets_severity(entry["cvss"]):
                            continue
                        vulns.append(Vulnerability(
                            package=pkg_name,
                            installed_version=version,
                            cve_id=entry["cve"],
                            cvss_score=entry["cvss"],
                            description=entry["description"],
                            fixed_version=entry["fixed_version"],
                        ))

        risk = self._compute_risk(vulns)
        return AssessmentResult(vulnerabilities=vulns, risk_score=risk)

    def _gather_dependencies(self) -> Dict[str, str]:
        """Walk up from target, parse known manifest files."""
        deps: Dict[str, str] = {}
        if not os.path.exists(self.target):
            return deps

        if os.path.isfile(self.target):
            roots = [os.path.dirname(self.target)]
        else:
            roots = [self.target]

        for root in roots:
            for fname in os.listdir(root):
                fpath = os.path.join(root, fname)
                if fname == "requirements.txt":
                    deps.update(self._parse_requirements_txt(fpath))
                elif fname == "pyproject.toml":
                    deps.update(self._parse_pyproject_toml(fpath))
                elif fname == "package.json":
                    deps.update(self._parse_package_json(fpath))
                elif fname == "go.mod":
                    deps.update(self._parse_go_mod(fpath))
        return deps

    @staticmethod
    def _parse_requirements_txt(path: str) -> Dict[str, str]:
        deps = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    # Handle ==, >=, ~=, etc.
                    match = re.match(r'^([a-zA-Z0-9_.-]+)\s*([><=!~]+)\s*([0-9.]+)', line)
                    if match:
                        deps[match.group(1).lower()] = match.group(3)
        except (OSError, PermissionError):
            pass
        return deps

    @staticmethod
    def _parse_pyproject_toml(path: str) -> Dict[str, str]:
        deps = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            # Simple TOML-ish parsing for [project] dependencies
            in_deps = False
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("[tool."):
                    in_deps = False
                if line == "[project]" or line.startswith("[project.dependencies]"):
                    in_deps = True
                    continue
                if in_deps and line.startswith("[") and not line.startswith("[project"):
                    in_deps = False
                if in_deps and "=" in line:
                    match = re.match(r'^["\']?([a-zA-Z0-9_.-]+)["\']?\s*=\s*["\'].*?\s*([><=!~]+)\s*([0-9.]+)["\']', line)
                    if not match:
                        match = re.match(r'^["\']?([a-zA-Z0-9_.-]+)(>=|==|~=)\s*([0-9.]+)', line)
                    if match:
                        deps[match.group(1).lower()] = match.group(3)
        except (OSError, PermissionError):
            pass
        return deps

    @staticmethod
    def _parse_package_json(path: str) -> Dict[str, str]:
        deps = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for key in ("dependencies", "devDependencies"):
                for pkg, ver in data.get(key, {}).items():
                    # Strip ^ ~ >= etc
                    clean = re.sub(r'^[\^~>=<]+', '', ver).split(" ")[0].split("||")[0]
                    deps[pkg.lower()] = clean
        except (OSError, PermissionError, json.JSONDecodeError):
            pass
        return deps

    @staticmethod
    def _parse_go_mod(path: str) -> Dict[str, str]:
        deps = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    # require github.com/foo/bar v1.2.3
                    match = re.match(r'^require\s+(\S+)\s+(v[0-9.]+)', line)
                    if match:
                        deps[match.group(1).lower()] = match.group(2).lstrip("v")
                    # Multi-line require block
                    match = re.match(r'^(\S+)\s+(v[0-9.]+)', line)
                    if match and not line.startswith("require") and not line.startswith("go ") and not line.startswith("exclude") and not line.startswith("replace"):
                        deps[match.group(1).lower()] = match.group(2).lstrip("v")
        except (OSError, PermissionError):
            pass
        return deps

    def _meets_severity(self, cvss: float) -> bool:
        thresholds = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.0}
        return cvss >= thresholds.get(self.min_severity, 0.0)

    @staticmethod
    def _compute_risk(vulns: List[Vulnerability]) -> float:
        if not vulns:
            return 0.0
        # Weighted average: critical = 10, high = 7, medium = 4, low = 1
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        scores = []
        for v in vulns:
            for label, weight in weights.items():
                threshold_map = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.0}
                if v.cvss_score >= threshold_map[label]:
                    scores.append(weight * min(v.cvss_score / 10.0, 1.0))
                    break
        if not scores:
            return 0.0
        raw = (sum(scores) / len(scores)) * 10
        return min(raw, 100.0)

    @staticmethod
    def exit_code(result: AssessmentResult) -> int:
        """0 = clean, 1 = high vulns, 2 = critical vulns."""
        if result.critical_count > 0:
            return 2
        if result.high_count > 0:
            return 1
        return 0
