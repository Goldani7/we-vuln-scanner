import asyncio

import httpx
import pytest

from scanner.checks.waf import SIGNATURES, check_waf, detect
from scanner.core import _looks_blocked, scan_target_async
from scanner.finding import Severity
from scanner.http import ScanConfig

from .conftest import make_response


def vendors(findings):
    return [f.metadata["vendor"] for f in findings if "vendor" in f.metadata]


def test_cloudflare_by_headers_and_cookie_is_high_confidence():
    r = make_response([("server", "cloudflare"), ("cf-ray", "8a1b2c-GRU"), ("set-cookie", "__cf_bm=abc; Path=/")])
    f = check_waf(r)[0]
    assert vendors([f]) == ["Cloudflare"] and f.confidence == "high" and f.severity is Severity.INFO
    assert "header cf-ray" in f.evidence and "cookie __cf_bm" in f.evidence
    assert "edge" in f.detail  # warns that Server/versions belong to the CDN, not the origin


def test_single_weak_indicator_is_medium_confidence():
    f = check_waf(make_response({"x-vercel-id": "gru1::abc"}))[0]
    assert vendors([f]) == ["Vercel"] and f.confidence == "medium"


@pytest.mark.parametrize("headers,expected", [
    ({"server": "AkamaiGHost"}, "Akamai"),
    ({"x-amz-cf-id": "abc", "via": "1.1 abc.cloudfront.net (CloudFront)"}, "Amazon CloudFront"),
    ({"x-served-by": "cache-gru1234-GRU", "x-fastly-request-id": "x"}, "Fastly"),
    ({"x-iinfo": "1-2-3"}, "Imperva / Incapsula"),
    ({"x-sucuri-id": "123"}, "Sucuri"),
    ({"x-azure-ref": "0abc"}, "Azure Front Door / App Gateway"),
    ({"server": "Apache/2.4.57 (mod_security)"}, "ModSecurity"),
])
def test_vendor_fingerprints(headers, expected):
    assert expected in vendors(check_waf(make_response(headers)))


def test_cookie_only_fingerprint():
    r = make_response([("set-cookie", "BIGipServerpool1=123.456.0000; path=/")])
    assert "F5 BIG-IP / ASM" in vendors(check_waf(r))


def test_multiple_layers_are_all_reported():
    r = make_response({"cf-ray": "x", "x-amz-cf-id": "y"})
    assert {"Cloudflare", "Amazon CloudFront"} <= set(vendors(check_waf(r)))


def test_no_waf_is_low_confidence_info_and_admits_limits():
    f = check_waf(make_response({"server": "nginx"}))[0]
    assert f.rule == "waf.none" and f.confidence == "low" and "doesn't prove" in f.detail


def test_block_page_is_detected_only_on_error_responses():
    body = "<title>Attention Required! | Cloudflare</title>"
    blocked = check_waf(make_response(status=403, body=body))
    assert {"waf.blocked"} <= {f.rule for f in blocked} and vendors(blocked) == ["Cloudflare"]
    assert detect(make_response(status=200, body=body)) == []  # 200 with this text is not a block


def test_blocked_status_with_vendor_headers_adds_blocked_notice():
    f = check_waf(make_response({"cf-ray": "x"}, status=429))
    assert "waf.blocked" in {x.rule for x in f}


def test_safe_when_headers_are_odd():
    assert check_waf(make_response({"cf-ray": ""}))[0].severity is Severity.INFO


def test_signature_table_is_well_formed():
    names = [s.name for s in SIGNATURES]
    assert len(names) == len(set(names))
    for s in SIGNATURES:
        assert s.kinds and (s.headers or s.cookies or s.body), s.name


def test_forbidden_ratio_heuristic():
    assert _looks_blocked({"forbidden": 20, "requests": 30})
    assert not _looks_blocked({"forbidden": 20, "requests": 100})  # 403 on protected files is normal
    assert not _looks_blocked({"forbidden": 5, "requests": 6})  # too few samples


def test_scan_warns_when_target_forbids_most_requests():
    def wall(request):
        return httpx.Response(200 if request.url.path == "/" else 403, headers={"cf-ray": "x"})
    cfg = ScanConfig(rate=0, retries=0)
    findings = asyncio.run(scan_target_async(
        "https://ex.com", "web", ["waf", "exposed_files", "misconfig"], cfg, transport=httpx.MockTransport(wall)))
    notice = [f for f in findings if f.rule == "core.throttled"]
    assert notice and notice[0].metadata["forbidden"] >= 10
    assert any(f.rule.startswith("waf.detected.cloudflare") for f in findings)
