from scanner.checks.headers import SECURITY_HEADERS, check_headers
from scanner.finding import Severity


class FakeResponse:
    def __init__(self, headers=None):
        self.headers = headers or {}


def _by_header(findings, name):
    return next(f for f in findings if f.metadata["header"] == name)


def test_missing_csp_is_high():
    f = _by_header(check_headers(FakeResponse()), "Content-Security-Policy")
    assert f.severity is Severity.HIGH
    assert f.recommendation


def test_present_header_is_info():
    resp = FakeResponse({"X-Frame-Options": "DENY"})
    f = _by_header(check_headers(resp), "X-Frame-Options")
    assert f.severity is Severity.INFO


def test_full_header_set_has_no_medium_or_high():
    resp = FakeResponse({name: "x" for name in SECURITY_HEADERS})
    findings = check_headers(resp)
    assert all(f.severity.rank < Severity.MEDIUM.rank for f in findings)
