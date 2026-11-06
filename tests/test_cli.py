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


def test_scan_target_modes_dispatch():
    with patch("scanner.core.scan", return_value=[]) as web, \
         patch("scanner.core.scan_email", return_value=[]) as mail:
        scan_target("ex.com", mode="web")
        assert web.call_args.args == ("https://ex.com",) and not mail.called
        web.reset_mock()
        scan_target("https://ex.com/x", mode="email")
        assert not web.called and mail.call_args.args == ("ex.com",)
        scan_target("ex.com", mode="full")
        assert web.called and mail.call_count == 2


def test_scan_target_rejects_bad_mode():
    with pytest.raises(ValueError):
        scan_target("ex.com", mode="x")
