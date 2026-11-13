import asyncio

import httpx
import pytest

from scanner.http import HttpClient, RequestFailed, ScanConfig
from scanner.netguard import is_blocked_ip, resolve_blocked, resolve_blocked_async


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254",
                                "0.0.0.0", "::1", "fe80::1", "::ffff:127.0.0.1", "100.64.0.1"])
def test_internal_ips_blocked(ip):
    assert is_blocked_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert not is_blocked_ip(ip)


def test_resolve_blocked_names_and_literals():
    assert resolve_blocked("localhost") and resolve_blocked("app.localhost")
    assert resolve_blocked("127.0.0.1") and resolve_blocked("[::1]")
    assert resolve_blocked("8.8.8.8") is None


def test_host_resolving_to_internal_ip_is_blocked(monkeypatch):
    monkeypatch.setattr("scanner.netguard._resolve", lambda h: ["10.1.2.3"])
    assert resolve_blocked("evil.example") == "10.1.2.3"


def test_redirect_to_cloud_metadata_is_blocked_before_following():
    """The reported SSRF: a public URL answers 302 -> internal address. It must NOT be requested."""
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.host == "8.8.8.8":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})
        return httpx.Response(200, text="SECRET-CREDENTIALS")

    async def go():
        cfg = ScanConfig(rate=0, retries=0, public_only=True)
        async with HttpClient(cfg, transport=httpx.MockTransport(handler)) as c:
            with pytest.raises(RequestFailed) as exc:
                await c.request("GET", "http://8.8.8.8/", follow_redirects=True)
            return exc.value, c.stats

    err, stats = asyncio.run(go())
    assert err.kind == "out_of_scope"
    assert seen == ["http://8.8.8.8/"]  # the metadata endpoint was never contacted
    assert stats["out_of_scope"] == 1


def test_public_only_off_by_default():
    async def go():
        async with HttpClient(ScanConfig(rate=0), transport=httpx.MockTransport(
                lambda r: httpx.Response(200))) as c:
            return (await c.request("GET", "http://127.0.0.1/")).status_code
    assert asyncio.run(go()) == 200


def test_resolve_blocked_async_internal_name(monkeypatch):
    async def fake(self, host, port, **kw):
        return [(2, 1, 6, "", ("192.168.0.9", 0))]
    monkeypatch.setattr("asyncio.base_events.BaseEventLoop.getaddrinfo", fake)
    assert asyncio.run(resolve_blocked_async("intranet.corp")) == "192.168.0.9"
