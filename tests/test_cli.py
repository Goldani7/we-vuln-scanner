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
         patch.dict("scanner.core.ASYNC_CHECKS", {"subdomains": sub, "subdomain_takeover": AsyncMock(return_value=[])}):
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


@pytest.mark.parametrize("name,marker", [("r.md", "# Security Report"), ("r.sarif", '"version": "2.1.0"')])
def test_output_md_and_sarif_by_extension(tmp_path, name, marker):
    out = tmp_path / name
    run(["-t", "ex.com", "-o", str(out)], HIGH)
    assert marker in out.read_text()


def test_list_checks_needs_no_target_and_shows_plugin_source(capsys):
    assert main(["--list-checks"]) == 0
    out = capsys.readouterr().out
    assert "exposed_files" in out and "builtin" in out and "SOURCE" in out


def test_active_checks_require_allow_active(capsys, tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("ex.com\n")
    from scanner.core import REGISTRY
    from scanner.registry import CheckSpec
    REGISTRY.register(CheckSpec("zz_intrusive", "response", lambda r: [], "web", "x", active=True))
    try:
        code, m = run(["-t", "ex.com", "--checks", "zz_intrusive"])
        assert code == 2 and not m.called and "--allow-active" in capsys.readouterr().err
        code, m = run(["-t", "ex.com", "--checks", "zz_intrusive", "--allow-active", "--scope", str(scope)])
        assert code == 0 and m.call_args.kwargs["config"].allow_active is True
    finally:
        del REGISTRY._specs["zz_intrusive"]


def test_rich_flag_prints_banner_and_table(capsys):
    pytest.importorskip("rich")
    code, m = run(["-t", "ex.com", "--rich", "--no-color"], [Finding("headers", Severity.HIGH, "achado rich")])
    out = capsys.readouterr().out
    assert code == 2 and "GOLDANI" in out.upper() and "achado rich" in out
    assert m.call_args.kwargs["progress_cb"] is not None


def test_rich_flag_still_writes_requested_output_file(tmp_path):
    pytest.importorskip("rich")
    out = tmp_path / "r.json"
    run(["-t", "ex.com", "--rich", "--no-color", "-o", str(out)], [Finding("x", Severity.LOW, "a")])
    assert out.exists()


def test_rich_without_library_fails_cleanly(monkeypatch, capsys):
    # Simulates the package's absence directly on the flag scanner.cli checks, instead of blocking
    # the import system: rich's own internal relative imports (e.g. `from .console import X` inside
    # rich/protocol.py) don't carry the name "rich" through __import__ and would slip past a
    # name-based block, making that kind of simulation fragile and version-dependent.
    from scanner import ui
    monkeypatch.setattr(ui, "RICH_AVAILABLE", False)
    code, m = run(["-t", "ex.com", "--rich"])
    assert code == 2 and not m.called and "pip install rich" in capsys.readouterr().err


# ---------- multi-target and config file ----------
def _go(argv, capsys, fake=None):
    """main() with scan_target faked; returns (exit code, captured scan kwargs, stderr)."""
    seen, kw = [], {}

    def default(t, **k):
        seen.append(t)
        kw.update(k)
        return []
    with patch("scanner.cli.scan_target", side_effect=fake or default) as m:
        code = main(argv)
    return code, seen, kw, capsys.readouterr().err, m


def test_targets_file_scans_each_target_and_dedupes(tmp_path, capsys):
    f = tmp_path / "t.txt"
    f.write_text("a.com\n# comment\nb.com  # trailing\n\na.com\n")
    code, seen, *_ = _go(["-T", str(f), "-m", "web"], capsys)
    assert code == 0 and seen == ["a.com", "b.com"]


def test_targets_file_combines_with_t_and_bad_files_fail(tmp_path, capsys):
    f = tmp_path / "t.txt"
    f.write_text("b.com\n")
    assert _go(["-t", "a.com", "-T", str(f)], capsys)[1] == ["a.com", "b.com"]
    assert _go(["-T", str(tmp_path / "nope.txt")], capsys)[0] == 2
    empty = tmp_path / "e.txt"
    empty.write_text("# nothing\n")
    assert _go(["-T", str(empty)], capsys)[0] == 2


def test_scope_is_all_or_nothing_for_target_lists(tmp_path, capsys):
    scope = tmp_path / "s.txt"
    scope.write_text("a.com\n")
    f = tmp_path / "t.txt"
    f.write_text("a.com\nb.com\n")
    code, seen, _, err, _ = _go(["-T", str(f), "--scope", str(scope)], capsys)
    assert code == 2 and "b.com" in err and seen == []


def test_config_file_sets_defaults_and_cli_wins(tmp_path, capsys):
    cfg = tmp_path / "wvs.toml"
    cfg.write_text('rate = 3\nmode = "web"\nheader = ["X-A: 1"]\nports = [22, 80]\nno-info = true\n')
    code, _, kw, _, _ = _go(["-t", "ex.com", "--config", str(cfg), "--rate", "7"], capsys)
    assert code == 0 and kw["mode"] == "web"
    assert kw["config"].rate == 7  # the flag beats the file
    assert kw["config"].headers == {"X-A": "1"} and kw["config"].ports == [22, 80]


@pytest.mark.parametrize("body", ["bogus = 1", 'rate = "fast"', 'mode = "nope"', "rate = ", 'rich = "yes"'])
def test_invalid_config_is_rejected(tmp_path, capsys, body):
    cfg = tmp_path / "wvs.toml"
    cfg.write_text(body + "\n")
    code, _, _, err, m = _go(["-t", "ex.com", "--config", str(cfg)], capsys)
    assert code == 2 and "Error" in err and not m.called


def test_probes_file_flag_rejects_bad_file(tmp_path, capsys):
    bad = tmp_path / "p.json"
    bad.write_text("nope")
    assert _go(["-t", "ex.com", "--probes-file", str(bad)], capsys)[0] == 2
