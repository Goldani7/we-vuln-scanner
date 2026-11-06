import asyncio
import ssl
import time

import httpx
import pytest

from scanner.http import (CIRCUIT_THRESHOLD, HttpClient, RateLimiter, RequestFailed, ScanConfig,
                          classify_error)


def run_client(handler, config=None, calls=None, **kw):
    sleeps = []

    async def fake_sleep(s):
        sleeps.append(s)

    async def main():
        cfg = config or ScanConfig(rate=0, retries=2)
        async with HttpClient(cfg, transport=httpx.MockTransport(handler), sleep=fake_sleep) as c:
            try:
                r = await c.request("GET", "https://ex.com/", **kw)
            except RequestFailed as e:
                r = e
            return r, c, sleeps
    return asyncio.run(main())


def test_retries_429_honoring_retry_after():
    n = {"i": 0}

    def handler(request):
        n["i"] += 1
        return httpx.Response(429, headers={"Retry-After": "3"}) if n["i"] < 3 else httpx.Response(200)
    r, c, sleeps = run_client(handler)
    assert r.status_code == 200 and sleeps == [3.0, 3.0]
    assert c.stats["throttled"] == 2 and c.stats["retries"] == 2


def test_retry_after_is_capped():
    r, c, sleeps = run_client(lambda req: httpx.Response(429, headers={"Retry-After": "9999"}),
                              ScanConfig(rate=0, retries=1, max_backoff=5))
    assert r.status_code == 429 and sleeps == [5.0]  # devolve a 429 final em vez de travar


def test_timeout_is_retried_then_classified():
    def handler(request):
        raise httpx.ReadTimeout("slow")
    r, c, sleeps = run_client(handler)
    assert isinstance(r, RequestFailed) and r.kind == "timeout"
    assert len(sleeps) == 2 and c.stats["failures"] == 1


def test_tls_errors_are_not_retried():
    def handler(request):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired")
    r, c, sleeps = run_client(handler)
    assert isinstance(r, RequestFailed) and r.kind == "tls" and sleeps == []


def test_classify_tls_via_cause():
    err = httpx.ConnectError("boom")
    err.__cause__ = ssl.SSLError("handshake")
    assert classify_error(err, "u").kind == "tls"


def test_custom_headers_and_user_agent_are_sent():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(200)
    cfg = ScanConfig(rate=0, headers={"X-Pentest": "ACME-42"}, user_agent="acme-scanner/1")
    run_client(handler, cfg)
    assert seen["x-pentest"] == "ACME-42" and seen["user-agent"] == "acme-scanner/1"


def test_circuit_breaker_stops_hammering_a_dead_host():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        raise httpx.ConnectError("refused")

    async def main():
        cfg = ScanConfig(rate=0, retries=0)
        async with HttpClient(cfg, transport=httpx.MockTransport(handler)) as c:
            kinds = []
            for _ in range(CIRCUIT_THRESHOLD + 3):
                try:
                    await c.request("GET", "https://dead.test/")
                except RequestFailed as e:
                    kinds.append(e.kind)
            return kinds
    kinds = asyncio.run(main())
    assert kinds[-1] == "circuit_open" and calls["n"] == CIRCUIT_THRESHOLD


def test_rate_limiter_spaces_requests():
    async def main():
        rl = RateLimiter(20)  # 50 ms entre requisições
        t = time.monotonic()
        for _ in range(4):
            await rl.wait()
        return time.monotonic() - t
    assert asyncio.run(main()) >= 0.14


def test_concurrency_limit_is_respected():
    state = {"cur": 0, "max": 0}

    async def main():
        async def slow(request):
            state["cur"] += 1
            state["max"] = max(state["max"], state["cur"])
            await asyncio.sleep(0.02)
            state["cur"] -= 1
            return httpx.Response(200)
        cfg = ScanConfig(rate=0, concurrency=3)
        async with HttpClient(cfg, transport=httpx.MockTransport(slow)) as c:
            await asyncio.gather(*[c.request("GET", "https://ex.com/") for _ in range(12)])
    asyncio.run(main())
    assert state["max"] <= 3
