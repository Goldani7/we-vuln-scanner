import asyncio

import httpx

from scanner.core import scan_target_async
from scanner.finding import Severity
from scanner.http import ScanConfig

CFG = dict(rate=0, retries=0)


def scan(handler, mode="web", checks=("headers", "cookies", "cors", "exposed_files", "misconfig"), **cfg):
    config = ScanConfig(**{**CFG, **cfg})
    return asyncio.run(scan_target_async(
        "https://ex.com", mode, list(checks), config, transport=httpx.MockTransport(handler)))


def test_unreachable_target_gives_single_classified_high_finding():
    def boom(request):
        raise httpx.ConnectError("refused")
    findings = [f for f in scan(boom) if f.severity is not Severity.INFO]
    assert len(findings) == 1 and findings[0].rule == "core.connect-connect"
    assert findings[0].severity is Severity.HIGH and findings[0].evidence.startswith("GET https://ex.com ")


def test_tls_failure_is_reported_with_actionable_message():
    def bad_cert(request):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired")
    f = scan(bad_cert)[0]
    assert f.rule == "core.connect-tls" and "--insecure" in f.remediation


def test_full_web_scan_tags_target_and_aggregates_checks():
    def site(request):
        if request.url.path == "/.env":
            return httpx.Response(200, text="DB_PASSWORD=x\nAPP_KEY=y\n")
        return httpx.Response(200, headers={"set-cookie": "sessionid=1"}, text="<html>ok</html>")
    findings = scan(site)
    checks = {f.check for f in findings}
    assert {"headers", "cookies", "cors", "exposed_files", "misconfig"} <= checks
    assert all(f.target == "https://ex.com" for f in findings)
    assert any(f.rule == "exposed.env" and f.severity is Severity.CRITICAL for f in findings)


def test_rate_limited_target_adds_incomplete_results_notice():
    n = {"i": 0}

    def limited(request):
        n["i"] += 1
        return httpx.Response(429, headers={"Retry-After": "0"}) if n["i"] % 2 else httpx.Response(200)
    notice = [f for f in scan(limited, retries=3) if f.rule == "core.throttled"]
    assert notice and "--rate" in notice[0].remediation and notice[0].metadata["throttled"] > 0


def test_a_crashing_check_does_not_break_the_scan():
    from unittest.mock import AsyncMock, patch
    with patch.dict("scanner.core.ASYNC_CHECKS", {"cors": AsyncMock(side_effect=RuntimeError("bug"))}):
        findings = scan(lambda r: httpx.Response(200, text="ok"))
    err = [f for f in findings if f.rule == "cors.error"]
    assert err and "RuntimeError: bug" in err[0].detail
    assert any(f.check == "headers" for f in findings)  # os outros checks seguiram


def test_deadline_cancels_slow_checks_and_reports_it():
    import asyncio

    from scanner import core

    async def fast(ctx):
        return [core.Finding("fast", core.Severity.LOW, "ok")]

    async def slow(ctx):
        await asyncio.sleep(30)
        return []

    jobs = [core._safe("fast", fast(None)), core._safe("slow", slow(None))]
    out = asyncio.run(core._gather_with_deadline(jobs, 0.2))
    assert any(f.title == "ok" for f in out)
    assert any(f.rule_id == "core.deadline" for f in out)
