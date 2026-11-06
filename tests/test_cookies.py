from scanner.checks.cookies import check_cookies
from scanner.finding import Severity

import httpx


def _resp(*set_cookies):
    return httpx.Response(200, headers=[("set-cookie", c) for c in set_cookies],
                          request=httpx.Request("GET", "https://ex.com"))


def test_no_cookies_is_info():
    assert check_cookies(_resp())[0].severity is Severity.INFO


def test_session_cookie_missing_flags_is_medium_without_leaking_value():
    f = check_cookies(_resp("sessionid=abc123SECRET; Path=/"))[0]
    assert f.severity is Severity.MEDIUM and set(f.metadata["missing"]) == {"Secure", "HttpOnly", "SameSite"}
    assert "abc123SECRET" not in f.evidence + f.detail


def test_non_session_cookie_is_low():
    assert check_cookies(_resp("theme=dark; Path=/"))[0].severity is Severity.LOW


def test_fully_flagged_cookie_is_info():
    f = check_cookies(_resp("sid=x; Secure; HttpOnly; SameSite=Lax"))[0]
    assert f.severity is Severity.INFO


def test_multiple_cookies_each_reported():
    names = [f.metadata["cookie"] for f in check_cookies(_resp("a=1", "sid=2; Secure; HttpOnly; SameSite=Lax"))]
    assert names == ["a", "sid"]
