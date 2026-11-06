from scanner.checks.headers import check_headers
from scanner.finding import Severity

from .conftest import make_response

GOOD = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def _rules(findings):
    return {f.rule: f for f in findings}


def test_missing_csp_is_medium_with_evidence():
    f = _rules(check_headers(make_response()))["headers.csp-missing"]
    assert f.severity is Severity.MEDIUM and f.evidence == "missing" and f.remediation


def test_good_headers_have_no_actionable_findings():
    findings = check_headers(make_response(GOOD))
    assert all(f.severity is Severity.INFO for f in findings), [f.title for f in findings]


def test_csp_unsafe_inline_is_flagged():
    h = {**GOOD, "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"}
    f = _rules(check_headers(make_response(h)))["headers.csp-unsafe-inline"]
    assert f.severity is Severity.MEDIUM and "unsafe-inline" in f.evidence


def test_csp_unsafe_inline_with_nonce_is_not_flagged():
    h = {**GOOD, "Content-Security-Policy": "script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"}
    assert "headers.csp-unsafe-inline" not in _rules(check_headers(make_response(h)))


def test_csp_wildcard_source():
    h = {**GOOD, "Content-Security-Policy": "default-src *"}
    assert "headers.csp-wildcard-source" in _rules(check_headers(make_response(h)))


def test_csp_report_only_does_not_count():
    h = {k: v for k, v in GOOD.items() if k != "Content-Security-Policy"}
    h["Content-Security-Policy-Report-Only"] = "default-src 'self'"
    f = _rules(check_headers(make_response(h)))["headers.csp-missing"]
    assert "Report-Only" in f.detail


def test_hsts_short_max_age_and_no_subdomains():
    h = {**GOOD, "Strict-Transport-Security": "max-age=300"}
    rules = _rules(check_headers(make_response(h)))
    assert rules["headers.hsts-short"].severity is Severity.LOW
    assert "headers.hsts-no-subdomains" in rules


def test_hsts_missing_only_matters_over_https():
    h = {k: v for k, v in GOOD.items() if k != "Strict-Transport-Security"}
    assert "headers.hsts-missing" in _rules(check_headers(make_response(h, url="https://ex.com")))
    assert "headers.hsts-missing" not in _rules(check_headers(make_response(h, url="http://ex.com")))


def test_xfo_covered_by_frame_ancestors():
    rules = _rules(check_headers(make_response(GOOD)))
    assert rules["headers.xfo-covered"].severity is Severity.INFO


def test_xfo_missing_without_frame_ancestors():
    h = {**GOOD, "Content-Security-Policy": "default-src 'self'"}
    assert _rules(check_headers(make_response(h)))["headers.xfo-missing"].severity is Severity.MEDIUM


def test_xfo_allow_from_is_obsolete():
    h = {**GOOD, "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "ALLOW-FROM https://a.com"}
    assert "headers.xfo-invalid" in _rules(check_headers(make_response(h)))


def test_nosniff_must_be_exact():
    h = {**GOOD, "X-Content-Type-Options": "sniff"}
    assert "headers.xcto-weak" in _rules(check_headers(make_response(h)))


def test_unsafe_referrer_policy():
    h = {**GOOD, "Referrer-Policy": "unsafe-url"}
    assert "headers.referrer-weak" in _rules(check_headers(make_response(h)))


def test_aspnet_version_leak():
    h = {**GOOD, "X-AspNet-Version": "4.0.30319"}
    assert _rules(check_headers(make_response(h)))["headers.leak-x-aspnet-version"].severity is Severity.LOW
