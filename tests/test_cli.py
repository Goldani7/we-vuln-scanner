import json
from unittest.mock import patch

import pytest

from scanner.cli import main
from scanner.core import extract_domain, scan_target
from scanner.finding import Finding, Severity

HIGH = [Finding("spf", Severity.HIGH, "SPF ausente")]
OK = [Finding("spf", Severity.INFO, "SPF presente")]


def run(argv, findings=OK):
    with patch("scanner.cli.scan_target", return_value=findings) as m:
        return main(argv), m


def test_target_flag_and_mode_are_forwarded():
    code, m = run(["-t", "ex.com", "-m", "email"])
    assert code == 0
    assert m.call_args.args == ("ex.com",) and m.call_args.kwargs["mode"] == "email"


def test_positional_target_still_works():
    _, m = run(["https://ex.com"])
    assert m.call_args.args == ("https://ex.com",)


def test_exit_code_2_on_high():
    assert run(["-t", "ex.com"], HIGH)[0] == 2


def test_missing_target_errors():
    with pytest.raises(SystemExit):
        main([])


def test_output_json_by_extension(tmp_path, capsys):
    out = tmp_path / "r.json"
    run(["-t", "ex.com", "-o", str(out)])
    assert json.loads(out.read_text())["target"] == "ex.com"
    assert "SPF presente" in capsys.readouterr().out


def test_output_html_by_extension(tmp_path):
    out = tmp_path / "r.html"
    run(["-t", "ex.com", "-o", str(out)])
    assert out.read_text().startswith("<!DOCTYPE html>")


def test_unknown_extension_is_rejected(tmp_path, capsys):
    code, m = run(["-t", "ex.com", "-o", str(tmp_path / "r.txt")])
    assert code == 2 and not m.called


def test_invalid_check_is_rejected():
    assert run(["-t", "ex.com", "--checks", "nope"])[0] == 2


@pytest.mark.parametrize("target,domain", [
    ("https://Ex.com:8443/path?q=1", "ex.com"), ("ex.com", "ex.com"), ("ex.com/a", "ex.com"),
])
def test_extract_domain(target, domain):
    assert extract_domain(target) == domain


def _dispatch(mode):
    from unittest.mock import AsyncMock
    web, mail, sub = AsyncMock(return_value=[]), AsyncMock(return_value=[]), AsyncMock(return_value=[])
    with patch("scanner.core.scan_web_async", web), patch("scanner.core.scan_email_async", mail), \
         patch.dict("scanner.core.ASYNC_CHECKS", {"subdomains": sub}):
        scan_target("https://Ex.com:8443/x", mode=mode)
    return web.called, mail.called, sub.called, mail


@pytest.mark.parametrize("mode,expected", [
    ("web", (True, False, False)), ("email", (False, True, False)),
    ("recon", (False, False, True)), ("full", (True, True, True)),
])
def test_scan_target_modes_dispatch(mode, expected):
    assert _dispatch(mode)[:3] == expected


def test_email_scan_receives_bare_domain():
    assert _dispatch("email")[3].call_args.args[0] == "ex.com"


def test_scan_target_rejects_bad_mode():
    with pytest.raises(ValueError):
        scan_target("ex.com", mode="x")


def test_network_options_build_scan_config():
    with patch("scanner.cli.scan_target", return_value=OK) as m:
        main(["-t", "ex.com", "--rate", "2", "--concurrency", "3", "--retries", "5",
              "--proxy", "socks5://127.0.0.1:9050", "-H", "X-Team: red", "-H", "Authorization: Bearer t",
              "--user-agent", "acme/1", "--insecure"])
    cfg = m.call_args.kwargs["config"]
    assert (cfg.rate, cfg.concurrency, cfg.retries, cfg.verify) == (2, 3, 5, False)
    assert cfg.proxy == "socks5://127.0.0.1:9050" and cfg.user_agent == "acme/1"
    assert cfg.headers == {"X-Team": "red", "Authorization": "Bearer t"}


def test_malformed_header_is_rejected():
    assert run(["-t", "ex.com", "-H", "sem-dois-pontos"])[0] == 2


@pytest.mark.parametrize("fail_on,sev,code", [
    ("high", Severity.HIGH, 2), ("high", Severity.MEDIUM, 0), ("critical", Severity.HIGH, 0),
    ("critical", Severity.CRITICAL, 2), ("low", Severity.LOW, 2), ("none", Severity.CRITICAL, 0),
])
def test_fail_on_threshold(fail_on, sev, code):
    assert run(["-t", "ex.com", "--fail-on", fail_on], [Finding("x", sev, "t")])[0] == code


@pytest.mark.parametrize("name,marker", [("r.md", "# Relatório"), ("r.sarif", '"version": "2.1.0"')])
def test_output_md_and_sarif_by_extension(tmp_path, name, marker):
    out = tmp_path / name
    run(["-t", "ex.com", "-o", str(out)], HIGH)
    assert marker in out.read_text()
