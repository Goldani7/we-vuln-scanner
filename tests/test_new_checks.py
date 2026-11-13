import asyncio
import json

import dns.exception
import dns.resolver
import httpx
import pytest

from scanner.checks import subdomains
from scanner.checks.api_exposure import check_api_exposure
from scanner.checks.dns_security import check_dns_security_sync
from scanner.checks.exposed_files import check_exposed_files, load_probes_file
from scanner.checks.open_redirect import PROBE_HOST, _candidates, check_open_redirect
from scanner.checks.takeover import check_subdomain_takeover, inspect_cname
from scanner.finding import Severity

from .conftest import run_check


# ---------- fake DNS ----------
class Ans(list):
    pass


class Target:
    def __init__(self, t):
        self.target = t


class FakeResolver:
    """records: {(name, rtype): list | Exception class}"""
    def __init__(self, records):
        self.records = records

    def resolve(self, name, rtype, *a, **k):
        v = self.records.get((str(name).rstrip("."), rtype), dns.resolver.NoAnswer)
        if isinstance(v, type) and issubclass(v, Exception):
            raise v()
        return Ans(v)


# ---------- takeover ----------
def test_dangling_claimable_cname_is_high():
    r = FakeResolver({("shop.ex.com", "CNAME"): [Target("old.azurewebsites.net.")],
                      ("old.azurewebsites.net", "A"): dns.resolver.NXDOMAIN})
    assert inspect_cname(r, "shop.ex.com") == ("old.azurewebsites.net", True)


def test_resolving_or_absent_cname_is_not_dangling():
    ok = FakeResolver({("a.ex.com", "CNAME"): [Target("lb.ex.net.")], ("lb.ex.net", "A"): ["1.2.3.4"]})
    assert inspect_cname(ok, "a.ex.com") is None
    assert inspect_cname(FakeResolver({}), "plain.ex.com") is None
    timeout = FakeResolver({("a.ex.com", "CNAME"): [Target("x.net.")], ("x.net", "A"): dns.exception.Timeout})
    assert inspect_cname(timeout, "a.ex.com") is None  # a timeout is not evidence


def test_takeover_check_end_to_end_shares_ct_lookup():
    calls = []

    def handler(req):
        calls.append(str(req.url))
        return httpx.Response(200, json=[{"name_value": "shop.ex.com\nwww.ex.com"}])

    res = FakeResolver({("shop.ex.com", "CNAME"): [Target("gone.example-unreg.org.")],
                        ("gone.example-unreg.org", "A"): dns.resolver.NXDOMAIN})

    async def both(ctx):
        a, b = await asyncio.gather(subdomains.check_subdomains(ctx), check_subdomain_takeover(ctx, res))
        return a, b

    from unittest.mock import patch

    async def fake_resolve(names, **kw):
        return {n: ["1.1.1.1"] for n in names}

    with patch.object(subdomains, "resolve_many", fake_resolve):
        _, takeover = run_check(both, handler)
    assert len(calls) == 1  # crt.sh queried once for both checks
    assert takeover[0].rule == "takeover.dangling-cname" and takeover[0].severity is Severity.MEDIUM
    assert "shop.ex.com" in takeover[0].title


# ---------- dns_security ----------
@pytest.fixture(autouse=True)
def _zone_is_the_domain(monkeypatch):
    monkeypatch.setattr("scanner.checks.dns_security._zone", lambda resolver, domain: domain)


def test_missing_caa_and_dnssec():
    r = FakeResolver({("ex.com", "CAA"): dns.resolver.NoAnswer, ("ex.com", "DS"): dns.resolver.NoAnswer})
    rules = {f.rule for f in check_dns_security_sync("ex.com", resolver=r)}
    assert rules == {"dns.no-caa", "dns.no-dnssec"}


def test_present_caa_and_dnssec_and_lookup_failures_are_quiet():
    ok = FakeResolver({("ex.com", "CAA"): ["0 issue x"], ("ex.com", "DS"): ["ds"]})
    assert {f.rule for f in check_dns_security_sync("ex.com", resolver=ok)} == {"dns.caa-ok", "dns.dnssec-ok"}
    broken = FakeResolver({("ex.com", "CAA"): dns.exception.Timeout, ("ex.com", "DS"): dns.exception.Timeout})
    assert check_dns_security_sync("ex.com", resolver=broken) == []  # never claim absence on a failure
    assert check_dns_security_sync("203.0.113.5") == []


# ---------- open redirect ----------
def test_candidates_include_links_with_redirect_params():
    html = '<a href="/login?next=/home&x=1">l</a><a href="https://other.com/?url=a">o</a>'
    cands = _candidates("https://ex.com/", html)
    assert cands[0].startswith("https://ex.com/login?") and PROBE_HOST in cands[0] and "x=1" in cands[0]
    assert not any("other.com" in c for c in cands)


def redirect_server(vulnerable):
    def handler(req):
        if req.url.path == "/" and not req.url.query:
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        target = req.url.params.get("next")
        if vulnerable and target:
            return httpx.Response(302, headers={"location": target})
        return httpx.Response(200, text="ok")
    return handler


def test_open_redirect_detected():
    f = run_check(check_open_redirect, redirect_server(True))
    assert f[0].rule == "redirect.open" and "next" in f[0].title and f[0].severity is Severity.MEDIUM


def test_safe_app_has_no_open_redirect():
    assert run_check(check_open_redirect, redirect_server(False))[0].rule == "redirect.none"


def test_same_host_redirect_is_not_open():
    def handler(req):
        return httpx.Response(302, headers={"location": "/home"}) if req.url.query else httpx.Response(200, text="x")
    assert run_check(check_open_redirect, handler)[0].rule == "redirect.none"


# ---------- graphql ----------
def test_graphql_introspection_enabled():
    def handler(req):
        if req.url.path == "/graphql" and req.method == "POST":
            return httpx.Response(200, json={"data": {"__schema": {"types": [{"name": "User"}, {"name": "__Type"}]}}})
        return httpx.Response(404)
    f = run_check(check_api_exposure, handler)
    assert f[0].rule == "api.graphql-introspection" and "User" in f[0].evidence


def test_graphql_disabled_or_spa_fallback_is_clean():
    spa = lambda req: httpx.Response(200, text="<html>app</html>")
    assert run_check(check_api_exposure, spa)[0].rule == "api.none"
    off = lambda req: httpx.Response(400, json={"errors": [{"message": "introspection disabled"}]})
    assert run_check(check_api_exposure, off)[0].rule == "api.none"


# ---------- custom probes ----------
def test_load_probes_file_and_detect(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps([{"path": "/config.old", "title": "Old config", "severity": "high",
                              "regex": "DB_PASSWORD\\s*=", "mask": True, "rule": "custom.old"}]))
    probes = load_probes_file(str(f))

    def handler(req):
        if req.url.path == "/config.old":
            return httpx.Response(200, text="DB_PASSWORD=hunter2\n", headers={"content-type": "text/plain"})
        return httpx.Response(404)
    found = run_check(check_exposed_files, handler, extra_probes=probes)
    hit = next(x for x in found if x.rule == "custom.old")
    assert hit.severity is Severity.HIGH and "hunter2" not in hit.evidence


@pytest.mark.parametrize("content", ["not json", "{}", '[{"path": "no-slash", "title": "t", "regex": "x"}]',
                                     '[{"path": "/a", "title": "t"}]', '[{"path": "/a", "title": "t", "regex": "("}]',
                                     '[{"path": "/a", "title": "t", "regex": "x", "severity": "huge"}]'])
def test_invalid_probes_file_is_rejected(tmp_path, content):
    f = tmp_path / "p.json"
    f.write_text(content)
    with pytest.raises(ValueError):
        load_probes_file(str(f))


def test_builtin_new_probes_reject_soft_404():
    spa = lambda req: httpx.Response(200, text="<!doctype html><html>app</html>", headers={"content-type": "text/html"})
    found = run_check(check_exposed_files, spa)
    assert [f.rule for f in found] == ["exposed.none"]


def test_open_redirect_title_names_the_vulnerable_param_not_the_first_one():
    html = '<html><a href="/go?id=7&next=/x">a</a></html>'

    def handler(req):
        if req.url.path == "/" and not req.url.query:
            return httpx.Response(200, text=html, headers={"content-type": "text/html"})
        if req.url.path == "/go" and req.url.params.get("next"):
            return httpx.Response(302, headers={"location": req.url.params["next"]})
        return httpx.Response(200, text="ok")
    f = run_check(check_open_redirect, handler)
    assert f[0].rule == "redirect.open" and "'next'" in f[0].title and "'id'" not in f[0].title
