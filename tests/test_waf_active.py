import httpx

from scanner.checks.waf_active import PROBE_PARAM, _probe_url, check_waf_active
from scanner.finding import Severity

from .conftest import run_check


def rules(findings):
    return {f.rule: f for f in findings}


def test_probe_url_appends_param_without_losing_existing_query():
    assert _probe_url("https://ex.com/x?a=1") == f"https://ex.com/x?a=1&{PROBE_PARAM}=../../../../etc/passwd"
    assert _probe_url("https://ex.com/x") == f"https://ex.com/x?{PROBE_PARAM}=../../../../etc/passwd"


def test_confirmed_when_baseline_ok_and_probe_blocked():
    def handler(request):
        if PROBE_PARAM in str(request.url):
            return httpx.Response(403, headers={"cf-ray": "abc"},
                                  text="Attention Required! | Cloudflare")
        return httpx.Response(200, text="home")
    f = rules(run_check(check_waf_active, handler))["waf_active.confirmed"]
    assert f.severity is Severity.INFO and f.confidence == "high"
    assert "Cloudflare" in f.metadata["vendors"] and "Active WAF confirmed (Cloudflare)" in f.title
    assert "GET https://ex.com/ → HTTP 200" in f.evidence


def test_confirmed_without_identifiable_vendor():
    def handler(request):
        return httpx.Response(406 if PROBE_PARAM in str(request.url) else 200)
    f = rules(run_check(check_waf_active, handler))["waf_active.confirmed"]
    assert f.metadata["vendors"] == [] and f.title == "Active WAF confirmed"


def test_no_block_observed_is_low_confidence_info():
    f = rules(run_check(check_waf_active, lambda r: httpx.Response(200)))["waf_active.no-block"]
    assert f.severity is Severity.INFO and f.confidence == "low"


def test_baseline_already_blocked_is_inconclusive_and_sends_no_probe():
    seen = []
    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(503)
    findings = run_check(check_waf_active, handler)
    assert findings[0].rule == "waf_active.inconclusive"
    assert len(seen) == 1  # a sonda nunca foi enviada


def test_baseline_unreachable_is_reported_without_crashing():
    def boom(request):
        raise httpx.ConnectError("refused")
    assert run_check(check_waf_active, boom)[0].rule == "waf_active.no-baseline"


def test_probe_request_failure_after_good_baseline():
    calls = {"n": 0}
    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200)
        raise httpx.ConnectError("reset")
    assert run_check(check_waf_active, handler)[0].rule == "waf_active.error"


def test_waf_active_is_registered_as_active_and_excluded_by_default():
    from scanner.core import REGISTRY, default_web_checks
    from scanner.http import ScanConfig
    assert REGISTRY.get("waf_active").active is True
    assert "waf_active" not in default_web_checks(ScanConfig())
    assert "waf_active" in default_web_checks(ScanConfig(allow_active=True))
