import asyncio
from unittest.mock import patch

import httpx
import pytest

from scanner.cli import main
from scanner.core import scan_target_async
from scanner.finding import Severity
from scanner.http import HttpClient, RequestFailed, ScanConfig
from scanner.scope import ScopeError, load_scope, parse_scope

SCOPE = """
# ACME-42 engagement
exemplo.com
*.api.exemplo.com
203.0.113.0/24
198.51.100.7
!interno.api.exemplo.com
"""


def test_exact_wildcard_and_exclusion_rules():
    s = parse_scope(SCOPE)
    assert s.allows("exemplo.com") and s.allows("EXEMPLO.COM.")
    assert not s.allows("www.exemplo.com")            # an exact entry does not include subdomains
    assert s.allows("v1.api.exemplo.com") and s.allows("a.b.api.exemplo.com")
    assert not s.allows("api.exemplo.com")            # *.x does not include x
    assert not s.allows("interno.api.exemplo.com")    # exclusion wins over the wildcard
    assert not s.allows("evil-exemplo.com") and not s.allows("exemplo.com.evil.com")


def test_ip_and_cidr_entries():
    s = parse_scope(SCOPE)
    assert s.allows("203.0.113.50") and s.allows("198.51.100.7")
    assert not s.allows("203.0.114.1") and not s.allows("198.51.100.8")


def test_exclusion_of_ip_inside_allowed_range():
    s = parse_scope("10.0.0.0/24\n!10.0.0.5\n")
    assert s.allows("10.0.0.4") and not s.allows("10.0.0.5")


def test_empty_and_garbage_hosts_are_denied():
    s = parse_scope("exemplo.com")
    assert not s.allows("") and not s.allows(None) and not s.allows("bad host")


@pytest.mark.parametrize("text", ["", "# just a comment\n", "!just-an-exclusion.com\n", "exemplo.com\nnot a host!\n", "1.2.3.4/99\n"])
def test_invalid_or_empty_scope_is_rejected(text):
    with pytest.raises(ScopeError):
        parse_scope(text)


def test_error_message_has_line_number():
    with pytest.raises(ScopeError, match=r":2: invalid entry"):
        parse_scope("ok.com\nfoo bar\n", "escopo.txt")


def test_load_missing_file():
    with pytest.raises(ScopeError, match="could not read"):
        load_scope("/nao/existe.txt")


def _client_request(handler, scope, url, **kw):
    async def main():
        cfg = ScanConfig(rate=0, retries=0, scope=scope)
        async with HttpClient(cfg, transport=httpx.MockTransport(handler)) as c:
            try:
                return await c.request("GET", url, **kw), c
            except RequestFailed as e:
                return e, c
    return asyncio.run(main())


def test_in_scope_request_is_sent():
    r, _ = _client_request(lambda req: httpx.Response(200), parse_scope("ex.com"), "https://ex.com/")
    assert r.status_code == 200


def test_out_of_scope_request_is_never_sent():
    sent = []
    def handler(req):
        sent.append(req)
        return httpx.Response(200)
    r, c = _client_request(handler, parse_scope("ex.com"), "https://outro.com/")
    assert isinstance(r, RequestFailed) and r.kind == "out_of_scope" and sent == []
    assert c.stats["out_of_scope"] == 1


def test_redirect_to_out_of_scope_host_is_blocked_before_following():
    hits = []
    def handler(req):
        hits.append(req.url.host)
        if req.url.host == "ex.com":
            return httpx.Response(302, headers={"location": "https://terceiro.com/login"})
        return httpx.Response(200, text="should never get here")
    r, _ = _client_request(handler, parse_scope("ex.com"), "https://ex.com/", follow_redirects=True)
    assert isinstance(r, RequestFailed) and r.kind == "out_of_scope"
    assert hits == ["ex.com"]  # the second host never received the request


def test_redirect_inside_scope_is_followed():
    def handler(req):
        if req.url.path == "/":
            return httpx.Response(302, headers={"location": "https://www.ex.com/home"})
        return httpx.Response(200)
    r, _ = _client_request(handler, parse_scope("ex.com\nwww.ex.com"), "https://ex.com/", follow_redirects=True)
    assert r.status_code == 200


def test_crtsh_passive_service_is_exempt():
    r, _ = _client_request(lambda req: httpx.Response(200, json=[]), parse_scope("ex.com"), "https://crt.sh/?q=x")
    assert r.status_code == 200


def test_no_scope_means_no_restriction():
    r, _ = _client_request(lambda req: httpx.Response(200), None, "https://qualquer.com/")
    assert r.status_code == 200


def test_full_scan_reports_blocked_redirect_instead_of_following():
    def handler(req):
        return httpx.Response(302, headers={"location": "https://terceiro.com/"})
    findings = asyncio.run(scan_target_async(
        "https://ex.com", "web", ["headers"], ScanConfig(rate=0, retries=0, scope=parse_scope("ex.com")),
        transport=httpx.MockTransport(handler)))
    blocked = [f for f in findings if f.rule == "core.connect-out_of_scope"]
    assert blocked and blocked[0].severity is Severity.INFO  # not a vulnerability of the target
    assert any(f.rule == "core.out-of-scope" for f in findings)


# --- CLI
def run(argv, findings=()):
    with patch("scanner.cli.scan_target", return_value=list(findings)) as m:
        return main(argv), m


def test_cli_blocks_out_of_scope_target_before_any_traffic(tmp_path, capsys):
    scope = tmp_path / "s.txt"
    scope.write_text("exemplo.com\n")
    code, m = run(["-t", "https://outro.com", "--scope", str(scope)])
    assert code == 2 and not m.called and "OUT of the scope" in capsys.readouterr().err


def test_cli_accepts_in_scope_target_and_passes_scope(tmp_path):
    scope = tmp_path / "s.txt"
    scope.write_text("*.exemplo.com\n")
    code, m = run(["-t", "https://app.exemplo.com/login", "--scope", str(scope)])
    assert code == 0 and m.call_args.kwargs["config"].scope.allows("app.exemplo.com")


def test_cli_rejects_bad_scope_file(tmp_path, capsys):
    scope = tmp_path / "s.txt"
    scope.write_text("")
    code, m = run(["-t", "ex.com", "--scope", str(scope)])
    assert code == 2 and not m.called


def test_allow_active_requires_scope():
    with pytest.raises(SystemExit):
        main(["-t", "ex.com", "--allow-active"])


def test_scope_file_is_recorded_in_json_report(tmp_path):
    import json
    scope, out = tmp_path / "s.txt", tmp_path / "r.json"
    scope.write_text("ex.com\n")
    run(["-t", "ex.com", "--scope", str(scope), "-o", str(out)])
    assert json.loads(out.read_text())["scope"] == str(scope)
