import pytest

from scanner.finding import Finding, Severity
from scanner.registry import CheckSpec, Registry


def noop(*a, **k):
    return []


def spec(name="my_check", **kw):
    kw.setdefault("kind", "response")
    kw.setdefault("func", noop)
    return CheckSpec(name=name, **kw)


class FakeEntryPoint:
    def __init__(self, name, obj=None, error=None):
        self.name, self._obj, self._error = name, obj, error

    def load(self):
        if self._error:
            raise self._error
        return self._obj


@pytest.mark.parametrize("kwargs", [
    {"name": "Bad-Name"}, {"name": "1abc"}, {"name": ""},
    {"kind": "banana"}, {"category": "other"}, {"func": "not callable"},
    {"category": "recon", "kind": "response"},
])
def test_invalid_specs_are_rejected(kwargs):
    with pytest.raises(ValueError):
        spec(**kwargs)


def test_register_and_query():
    r = Registry()
    r.register(spec("a", category="web"))
    r.register(spec("b", category="email", kind="domain"))
    r.register(spec("c", category="web", active=True))
    assert r.names("web") == ["a"] and r.names("web", include_active=True) == ["a", "c"]
    assert r.names() == ["a", "b"] and "b" in r and "zzz" not in r
    assert set(r.by_kind("response")) == {"a", "c"} and r.get("b").kind == "domain"


def test_duplicate_names_are_rejected():
    r = Registry()
    r.register(spec("a"))
    with pytest.raises(ValueError, match="already registered"):
        r.register(spec("a"))


def test_plugins_load_and_are_tagged_with_their_source():
    r = Registry()
    loaded = r.load_plugins([FakeEntryPoint("acme", spec("acme_check")),
                             FakeEntryPoint("multi", [spec("m1"), spec("m2")])])
    assert loaded == ["acme_check", "m1", "m2"]
    assert r.get("acme_check").source == "plugin:acme" and r.get("m2").source == "plugin:multi"


def test_broken_plugins_are_isolated_and_reported():
    r = Registry()
    r.register(spec("builtin"))
    loaded = r.load_plugins([
        FakeEntryPoint("boom", error=ImportError("no module")),
        FakeEntryPoint("wrong", obj=lambda: None),               # not a CheckSpec
        FakeEntryPoint("clash", obj=spec("builtin")),            # tenta sobrescrever um embutido
        FakeEntryPoint("good", obj=spec("good_check")),
    ])
    assert loaded == ["good_check"] and r.get("builtin").source == "builtin"
    assert {name for name, _ in r.plugin_errors} == {"boom", "wrong", "clash"}
    assert any("ImportError" in msg for _, msg in r.plugin_errors)


def test_builtin_registry_matches_documented_checks():
    from scanner.core import ALL_CHECKS, EMAIL_CHECKS, RECON_CHECKS, REGISTRY
    assert {"headers", "cookies", "tech_detection", "waf", "ssl_tls", "cors", "exposed_files",
            "misconfig", "html_security", "js_libs", "dns_security", "api_exposure"} <= set(ALL_CHECKS)
    assert "open_redirect" not in ALL_CHECKS  # active: only with --allow-active
    assert EMAIL_CHECKS == ["spf", "dkim", "dmarc", "dnsbl"]
    assert RECON_CHECKS == ["subdomains", "subdomain_takeover"]
    assert all(REGISTRY.description(n) for n in REGISTRY.names(include_active=True))


def test_plugin_check_runs_through_the_scan_pipeline():
    import asyncio

    import httpx

    from scanner import core
    from scanner.http import ScanConfig

    def custom(response):
        return [Finding("custom", Severity.LOW, "achado do plugin", rule_id="custom.x")]

    with pytest.MonkeyPatch.context() as mp:
        mp.setitem(core.RESPONSE_CHECKS, "custom", custom)
        findings = asyncio.run(core.scan_target_async(
            "https://ex.com", "web", ["custom"], ScanConfig(rate=0, retries=0),
            transport=httpx.MockTransport(lambda r: httpx.Response(200))))
    assert [f.rule for f in findings] == ["custom.x"] and findings[0].target == "https://ex.com"


def test_active_checks_only_enter_defaults_when_allowed():
    from scanner.core import REGISTRY, default_web_checks
    from scanner.http import ScanConfig
    REGISTRY.register(spec("zz_active", active=True))
    try:
        assert "zz_active" not in default_web_checks(ScanConfig())
        assert "zz_active" in default_web_checks(ScanConfig(allow_active=True))
    finally:
        del REGISTRY._specs["zz_active"]


def test_example_plugin_works_if_installed():
    mod = pytest.importorskip("wvs_cache_control")
    import httpx
    hdr = [("set-cookie", "sid=1")]
    resp = lambda extra: httpx.Response(200, headers=hdr + extra, request=httpx.Request("GET", "https://x"))
    assert mod.check_cache_control(resp([]))[0].severity is Severity.MEDIUM
    assert mod.check_cache_control(resp([("cache-control", "no-store")]))[0].severity is Severity.INFO
    assert mod.SPEC.kind == "response" and mod.SPEC.name == "cache_control"
