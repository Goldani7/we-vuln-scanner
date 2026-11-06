import httpx

from scanner.checks.cors import check_cors
from scanner.finding import Severity

from .conftest import run_check


def cors_server(reflect=False, creds=False, star=False, null_ok=False):
    def handler(request):
        origin = request.headers.get("origin")
        h = {}
        if reflect and (origin != "null" or null_ok):
            h["access-control-allow-origin"] = origin
        elif star:
            h["access-control-allow-origin"] = "*"
        if creds and h:
            h["access-control-allow-credentials"] = "true"
        return httpx.Response(200, headers=h)
    return handler


def test_reflected_origin_with_credentials_is_high():
    f = run_check(check_cors, cors_server(reflect=True, creds=True))[0]
    assert f.severity is Severity.HIGH and "evil-example-probe" in f.evidence


def test_reflected_origin_without_credentials_is_low():
    assert run_check(check_cors, cors_server(reflect=True))[0].severity is Severity.LOW


def test_null_origin_with_credentials_is_high():
    findings = run_check(check_cors, cors_server(reflect=True, creds=True, null_ok=True))
    assert any("null" in f.title and f.severity is Severity.HIGH for f in findings)


def test_wildcard_with_credentials_is_medium():
    assert run_check(check_cors, cors_server(star=True, creds=True))[0].severity is Severity.MEDIUM


def test_wildcard_is_low():
    assert run_check(check_cors, cors_server(star=True))[0].severity is Severity.LOW


def test_no_cors_is_info():
    assert run_check(check_cors, cors_server())[0].severity is Severity.INFO


def test_unreachable_target_is_reported_not_raised():
    def boom(request):
        raise httpx.ConnectError("refused")
    assert run_check(check_cors, boom)[0].severity is Severity.INFO
