import asyncio

import httpx

from scanner.http import HttpClient, ScanConfig, ScanContext


async def _no_sleep(_):
    return None


def make_response(headers=None, url="https://ex.com/", status=200, body=""):
    return httpx.Response(status, headers=headers or {}, text=body,
                          request=httpx.Request("GET", url))


def run_check(check, handler, url="https://ex.com/", retries=0, **cfg):
    """Executa um check async contra um MockTransport (sem rede)."""
    async def main():
        config = ScanConfig(rate=0, retries=retries, **cfg)
        async with HttpClient(config, transport=httpx.MockTransport(handler), sleep=_no_sleep) as client:
            return await check(ScanContext(url, client, config))
    return asyncio.run(main())
