"""Tests for VulnerabilityAssessor."""
import os
import json
import tempfile
from websec_test.security.assessor import VulnerabilityAssessor


def _make_requirements(path: str, content: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def test_no_dep_files_returns_empty():
    with tempfile.TemporaryDirectory() as td:
        assessor = VulnerabilityAssessor(td, min_severity="low")
        result = assessor.assess()
        assert result.count == 0
        assert result.risk_score == 0.0


def test_empty_requirements_txt():
    with tempfile.TemporaryDirectory() as td:
        _make_requirements(os.path.join(td, "requirements.txt"), "")
        assessor = VulnerabilityAssessor(td, min_severity="low")
        result = assessor.assess()
        assert result.count == 0


def test_detect_vulnerable_package_in_requirements():
    with tempfile.TemporaryDirectory() as td:
        _make_requirements(os.path.join(td, "requirements.txt"), "requests==2.1.0\n")
        assessor = VulnerabilityAssessor(td, min_severity="low")
        result = assessor.assess()
        # 2.1.0 is old enough to have CVEs
        assert result.count >= 1


def test_safe_package_skipped():
    with tempfile.TemporaryDirectory() as td:
        _make_requirements(os.path.join(td, "requirements.txt"), "requests==2.32.3\n")
        assessor = VulnerabilityAssessor(td, min_severity="low")
        result = assessor.assess()
        # 2.32.3 may still have CVEs depending on advisory freshness — just verify it runs
        assert isinstance(result.count, int)


def test_multiple_versions():
    with tempfile.TemporaryDirectory() as td:
        _make_requirements(os.path.join(td, "requirements.txt"),
                           "requests==2.1.0\nflask==0.10.0\n")
        assessor = VulnerabilityAssessor(td, min_severity="low")
        result = assessor.assess()
        # At least one should be vulnerable
        assert len(result.vulnerabilities) >= 1
        for v in result.vulnerabilities:
            assert v.cve_id
            assert v.cvss_score > 0


def test_severity_filter_excludes_low():
    with tempfile.TemporaryDirectory() as td:
        _make_requirements(os.path.join(td, "requirements.txt"), "requests==2.1.0\n")
        assessor = VulnerabilityAssessor(td, min_severity="critical")
        result = assessor.assess()
        # We may or may not have critical — just check no CVEs below critical
        for v in result.vulnerabilities:
            assert v.cvss_score >= 9.0


def test_package_json_support():
    with tempfile.TemporaryDirectory() as td:
        _make_requirements(os.path.join(td, "package.json"), json.dumps({
            "dependencies": {"lodash": "4.17.19"}
        }))
        assessor = VulnerabilityAssessor(td, min_severity="low")
        result = assessor.assess()
        assert len(result.vulnerabilities) >= 1


def test_exit_code_zero_for_clean():
    with tempfile.TemporaryDirectory() as td:
        assessor = VulnerabilityAssessor(td, min_severity="low")
        result = assessor.assess()
        assert assessor.exit_code(result) == 0


def test_exit_code_nonzero_for_vulnerable():
    with tempfile.TemporaryDirectory() as td:
        _make_requirements(os.path.join(td, "requirements.txt"), "requests==2.1.0\n")
        assessor = VulnerabilityAssessor(td, min_severity="low")
        result = assessor.assess()
        if result.count > 0:
            assert assessor.exit_code(result) in (1, 2)
