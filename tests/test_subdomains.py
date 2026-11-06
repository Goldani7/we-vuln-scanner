import asyncio
from unittest.mock import patch

import httpx

from scanner.checks import subdomains
from scanner.checks.subdomains import check_subdomains, parse_crtsh
from scanner.finding import Severity

from .conftest import run_check

PAYLOAD = [
    {"name_value": "ex.com\nwww.ex.com"},
    {"name_value": "*.ex.com\nstaging.ex.com"},
    {"name_value": "mail.ex.com\nevil.com\nnotex.com\nfoo.notex.com"},
    {"name_value": "WWW.EX.COM"},
]


def test_parse_dedups_normalizes_and_filters_foreign_names():
    assert parse_crtsh(PAYLOAD, "ex.com") == ["mail.ex.com", "staging.ex.com", "www.ex.com"]


def test_parse_ignores_garbage():
    assert parse_crtsh({"error": "x"}, "ex.com") == [] and parse_crtsh([{"name_value": "a b.ex.com"}], "ex.com") == []


def _run(handler, resolved):
    async def fake_resolve(names, **kw):
        return {n: resolved.get(n, []) for n in names}
    with patch.object(subdomains, "resolve_many", fake_resolve):
        return run_check(check_subdomains, handler)


def test_discovery_sensitive_names_and_private_ips():
    handler = lambda req: httpx.Response(200, json=PAYLOAD)
    findings = _run(handler, {"www.ex.com": ["93.184.216.34"], "staging.ex.com": ["10.0.0.5"]})
    by = {f.rule: f for f in findings}
    assert "3 subdomains" in by["subdomains.discovered"].title
    assert "staging.ex.com → 10.0.0.5" in by["subdomains.discovered"].evidence
    assert by["subdomains.sensitive-names"].severity is Severity.LOW
    assert by["subdomains.private-ip"].metadata["subdomains"] == {"staging.ex.com": ["10.0.0.5"]}


def test_non_resolving_sensitive_name_is_not_flagged():
    handler = lambda req: httpx.Response(200, json=PAYLOAD)
    rules = {f.rule for f in _run(handler, {"www.ex.com": ["93.184.216.34"]})}
    assert "subdomains.sensitive-names" not in rules


def test_crtsh_down_is_graceful():
    for handler in (lambda req: httpx.Response(502), lambda req: httpx.Response(200, text="<html>nope")):
        f = _run(handler, {})
        assert [x.rule for x in f] == ["subdomains.unavailable"] and f[0].severity is Severity.INFO


def test_ip_targets_are_skipped():
    f = run_check(check_subdomains, lambda req: httpx.Response(500), url="https://127.0.0.1/")
    assert f[0].rule == "subdomains.skipped"


def test_resolve_many_handles_failures():
    async def main():
        loop = asyncio.get_running_loop()

        async def fake(name, *a, **k):
            if name == "ok.ex.com":
                return [(2, 1, 6, "", ("1.2.3.4", 0))]
            raise OSError("nxdomain")
        with patch.object(loop, "getaddrinfo", fake):
            return await subdomains.resolve_many(["ok.ex.com", "bad.ex.com"])
    assert asyncio.run(main()) == {"ok.ex.com": ["1.2.3.4"], "bad.ex.com": []}
