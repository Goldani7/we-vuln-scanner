import httpx

from scanner.checks.misconfig import check_misconfig
from scanner.finding import Severity

from .conftest import run_check

LISTING = '<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1>' \
          '<a href="../">../</a><a href="dump.sql">dump.sql</a><a href="logo.png">logo.png</a></body></html>'


def rules(findings):
    return {f.rule: f for f in findings}


def handler_factory(**over):
    def handler(request):
        path, method, scheme = request.url.path, request.method, request.url.scheme
        if scheme == "http":
            return over.get("http", httpx.Response(301, headers={"location": "https://ex.com/"}))
        if method == "TRACE":
            return over.get("trace", httpx.Response(405))
        if method == "OPTIONS":
            return over.get("options", httpx.Response(200, headers={"allow": "GET, POST, HEAD, OPTIONS"}))
        if path == "/uploads/":
            return over.get("uploads", httpx.Response(404))
        if path == "/.well-known/security.txt":
            return over.get("sectxt", httpx.Response(404))
        return over.get("other", httpx.Response(404, text="not found"))
    return handler


def test_clean_server_has_no_actionable_findings():
    findings = run_check(check_misconfig, handler_factory())
    assert all(f.severity is Severity.INFO for f in findings)
    assert "misconfig.https-redirect-ok" in rules(findings)


def test_http_without_redirect_is_medium():
    f = rules(run_check(check_misconfig, handler_factory(http=httpx.Response(200, text="hi"))))
    assert f["misconfig.no-https-redirect"].severity is Severity.MEDIUM


def test_https_redirect_check_skipped_for_http_targets():
    f = rules(run_check(check_misconfig, handler_factory(http=httpx.Response(200)), url="http://ex.com/"))
    assert "misconfig.no-https-redirect" not in f


def test_trace_confirmed_by_echo():
    echo = httpx.Response(200, text="TRACE / HTTP/1.1\nX-WVS-Probe: trace-echo")
    f = rules(run_check(check_misconfig, handler_factory(trace=echo)))
    assert f["misconfig.trace"].severity is Severity.MEDIUM and f["misconfig.trace"].confidence == "high"


def test_trace_listed_in_allow_but_not_echoed_is_not_reported():
    opts = httpx.Response(200, headers={"allow": "GET, TRACE"})
    assert "misconfig.trace" not in rules(run_check(check_misconfig, handler_factory(options=opts)))


def test_put_delete_in_allow_is_low_confidence():
    opts = httpx.Response(200, headers={"allow": "GET, PUT, DELETE"})
    f = rules(run_check(check_misconfig, handler_factory(options=opts)))["misconfig.methods"]
    assert f.severity is Severity.LOW and f.confidence == "low"


def test_directory_listing_with_sensitive_file_is_high():
    f = rules(run_check(check_misconfig, handler_factory(uploads=httpx.Response(200, text=LISTING))))
    d = f["misconfig.dir-listing"]
    assert d.severity is Severity.HIGH and "dump.sql" in d.evidence


def test_stack_trace_disclosure_is_detected():
    body = 'Traceback (most recent call last):\n  File "/srv/app/views.py", line 10, in index'
    f = rules(run_check(check_misconfig, handler_factory(other=httpx.Response(500, text=body))))
    assert f["misconfig.error-disclosure"].severity is Severity.MEDIUM


def test_security_txt_present():
    f = rules(run_check(check_misconfig, handler_factory(sectxt=httpx.Response(200, text="Contact: mailto:s@ex.com"))))
    assert "misconfig.security-txt-ok" in f and "misconfig.security-txt-missing" not in f
