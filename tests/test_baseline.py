import json

import pytest

from scanner.baseline import BaselineError, annotate, compare, load_baseline
from scanner.cli import main
from scanner.finding import Finding, Severity
from scanner.report import to_markdown, to_sarif, to_text

from unittest.mock import patch


def F(title, sev=Severity.HIGH, rule="r"):
    return Finding("c", sev, title, rule_id=rule, target="https://ex.com")


def write_baseline(tmp_path, findings, wrapped=True):
    items = [f.to_dict() for f in findings]
    path = tmp_path / "base.json"
    path.write_text(json.dumps({"schema_version": "1.0", "findings": items} if wrapped else items))
    return str(path)


def test_compare_classifies_new_unchanged_and_resolved(tmp_path):
    old = [F("antigo-persiste"), F("corrigido"), F("so-info", Severity.INFO)]
    base = load_baseline(write_baseline(tmp_path, old))
    now = [F("antigo-persiste"), F("novo"), F("info-novo", Severity.INFO)]
    cmp = compare(now, base, "base.json")
    assert [f.title for f in cmp.new] == ["novo"]
    assert [f.title for f in cmp.unchanged] == ["antigo-persiste"]
    assert [r["title"] for r in cmp.resolved] == ["corrigido"]  # INFO nunca conta como resolvido
    assert cmp.summary()["resolved_findings"][0]["severity"] == "high"


def test_annotate_marks_status_and_leaves_info_blank():
    base = {F("a").fingerprint: F("a").to_dict()}
    findings = [F("a"), F("b"), F("c", Severity.INFO)]
    out = annotate(findings, compare(findings, base))
    assert [f.status for f in out] == ["unchanged", "new", ""]


def test_load_accepts_plain_list(tmp_path):
    assert F("x").fingerprint in load_baseline(write_baseline(tmp_path, [F("x")], wrapped=False))


@pytest.mark.parametrize("content,msg", [
    ("nao e json", "JSON válido"), ('{"foo": 1}', "lista de findings"),
    ('{"findings": [{"title": "sem fingerprint"}]}', "fingerprint"),
])
def test_load_rejects_bad_files(tmp_path, content, msg):
    p = tmp_path / "b.json"
    p.write_text(content)
    with pytest.raises(BaselineError, match=msg):
        load_baseline(str(p))


def test_load_missing_file():
    with pytest.raises(BaselineError, match="não foi possível ler"):
        load_baseline("/nao/existe.json")


def test_same_finding_on_different_target_counts_as_new(tmp_path):
    base = load_baseline(write_baseline(tmp_path, [F("x")]))
    other = Finding("c", Severity.HIGH, "x", rule_id="r", target="https://outro.com")
    assert compare([other], base).new == [other]


# --- integração com CLI e relatórios
def run(argv, findings):
    with patch("scanner.cli.scan_target", return_value=findings):
        return main(argv)


def test_cli_fails_only_on_new_findings_with_new_only(tmp_path, capsys):
    base = write_baseline(tmp_path, [F("conhecido")])
    # achado crítico já conhecido: com --new-only não derruba o CI
    assert run(["-t", "ex.com", "--baseline", base, "--new-only"], [F("conhecido", Severity.CRITICAL)]) == 0
    # sem --new-only o mesmo achado derruba
    assert run(["-t", "ex.com", "--baseline", base], [F("conhecido")]) == 2
    # achado novo derruba
    assert run(["-t", "ex.com", "--baseline", base, "--new-only"], [F("novo")]) == 2
    assert "(NOVO)" in capsys.readouterr().out


def test_cli_text_reports_baseline_counts(tmp_path, capsys):
    base = write_baseline(tmp_path, [F("corrigido"), F("fica")])
    run(["-t", "ex.com", "--baseline", base], [F("fica"), F("novo")])
    out = capsys.readouterr().out
    assert "1 novo(s), 1 inalterado(s), 1 resolvido(s)" in out


def test_cli_rejects_bad_baseline_before_scanning(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text("{")
    with patch("scanner.cli.scan_target") as scan:
        assert main(["-t", "ex.com", "--baseline", str(bad)]) == 2
    assert not scan.called


def test_new_only_requires_baseline():
    with pytest.raises(SystemExit):
        main(["-t", "ex.com", "--new-only"])


def test_json_report_round_trips_as_next_baseline(tmp_path):
    out = tmp_path / "r.json"
    run(["-t", "ex.com", "-o", str(out)], [F("a"), F("b", Severity.MEDIUM)])
    assert run(["-t", "ex.com", "--baseline", str(out), "--new-only", "--fail-on", "low"],
               [F("a"), F("b", Severity.MEDIUM)]) == 0


def test_sarif_and_markdown_carry_baseline_state(tmp_path):
    base = {F("a").fingerprint: F("a").to_dict(), F("gone").fingerprint: F("gone").to_dict()}
    findings = [F("a"), F("b")]
    cmp = compare(findings, base, "base.json")
    annotated = annotate(findings, cmp)
    meta = {"target": "https://ex.com", "baseline": cmp.summary()}
    states = [r["baselineState"] for r in json.loads(to_sarif(annotated, meta))["runs"][0]["results"]]
    assert sorted(states) == ["new", "unchanged"]
    md = to_markdown(annotated, meta)
    assert "## Comparação com baseline" in md and "**1 novo(s)**" in md and "| gone | high |" in md
    assert "**NOVO**" in md
