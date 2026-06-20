"""Tests for payload library."""
from websec_test.config.payloads import (
    SQLI_PAYLOADS, XSS_PAYLOADS, CMD_INJECT_PAYLOADS, COMMON_PATHS,
    NOSQLI_PAYLOADS,
)


def test_sqli_payloads_nonempty():
    assert len(SQLI_PAYLOADS) > 0


def test_xss_payloads_nonempty():
    assert len(XSS_PAYLOADS) > 0


def test_cmd_payloads_nonempty():
    assert len(CMD_INJECT_PAYLOADS) > 0


def test_common_paths_nonempty():
    assert len(COMMON_PATHS) > 0


def test_sqli_contains_basic_bypass():
    assert any("OR" in p.upper() for p in SQLI_PAYLOADS)


def test_xss_contains_script_tag():
    assert any("<script>" in p for p in XSS_PAYLOADS)


def test_sqli_has_new_payloads():
    assert len(SQLI_PAYLOADS) >= 10
    assert any("DROP TABLE" in p for p in SQLI_PAYLOADS)
    assert any("UNION SELECT 1,2,3" in p for p in SQLI_PAYLOADS)


def test_xss_has_img_onerror():
    assert any("onerror" in p for p in XSS_PAYLOADS)


def test_xss_has_body_onload():
    assert any("onload" in p for p in XSS_PAYLOADS)


def test_cmd_has_windows_specific():
    assert any("dir" in p for p in CMD_INJECT_PAYLOADS)
    assert any("type" in p for p in CMD_INJECT_PAYLOADS)
    assert any("`ls`" in p for p in CMD_INJECT_PAYLOADS)


def test_common_paths_has_new():
    assert any(".git" in p for p in COMMON_PATHS)
    assert any(".env" in p for p in COMMON_PATHS)
    assert any("actuator" in p for p in COMMON_PATHS)
    assert any("graphql" in p for p in COMMON_PATHS)


def test_nosql_payloads_nonempty():
    assert len(NOSQLI_PAYLOADS["auth_bypass"]) >= 5
    assert len(NOSQLI_PAYLOADS["field_injection"]) >= 2


def test_destructive_payloads_excluded():
    """Verify $eval/$where/$function/$accumulator are NOT in NOSQLI_PAYLOADS."""
    excluded = ["$eval", "$where", "$function", "$accumulator"]
    for category, payloads in NOSQLI_PAYLOADS.items():
        for payload in payloads:
            payload_str = repr(payload)
            for keyword in excluded:
                assert keyword not in payload_str, (
                    f"Destructive payload '{keyword}' found in {category}: {payload}"
                )
