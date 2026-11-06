import json

from scanner.finding import Finding, Severity
from scanner.report import summary, to_html, to_json, to_markdown, to_sarif, to_text


def _findings():
    return [
        Finding("headers", Severity.HIGH, "CSP ausente", "detalhe", "corrija",
                evidence="Content-Security-Policy: ausente", cwe="CWE-693",
                references=["https://owasp.org/x"], rule_id="headers.csp-missing", target="https://ex.com/"),
        Finding("exposed_files", Severity.CRITICAL, ".env exposto", remediation="remova",
                evidence="DB_PASSWORD=****", rule_id="exposed.env", target="https://ex.com/"),
        Finding("tls", Severity.INFO, "TLS 1.3"),
    ]


def test_json_without_meta_is_a_list_sorted_by_severity():
    data = json.loads(to_json(_findings()))
    assert [d["severity"] for d in data] == ["critical", "high", "info"]


def test_json_with_meta_is_versioned():
    data = json.loads(to_json(_findings(), {"target": "ex.com", "mode": "full"}))
    assert data["schema_version"] == "1.0" and data["tool"]["name"] == "web-vuln-scanner"
    assert data["summary"] == {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1}
    f = data["findings"][0]
    assert f["rule_id"] == "exposed.env" and f["evidence"] and f["remediation"] and f["fingerprint"]


def test_fingerprint_is_stable_and_target_specific():
    a = Finding("c", Severity.LOW, "t", target="https://a")
    assert a.fingerprint == Finding("c", Severity.LOW, "t", target="https://a").fingerprint
    assert a.fingerprint != Finding("c", Severity.LOW, "t", target="https://b").fingerprint


def test_text_shows_evidence_and_fix():
    out = to_text(_findings())
    assert "[CRÍTICO]" in out and "Evidência: DB_PASSWORD=****" in out and "Correção: remova" in out


def test_markdown_structure():
    md = to_markdown(_findings(), {"target": "https://ex.com", "mode": "web"})
    assert md.startswith("# Relatório de segurança")
    assert "| CRÍTICO | 1 |" in md and "### 1. [CRÍTICO] .env exposto" in md
    assert "```text\nDB_PASSWORD=****\n```" in md and "**Correção:** remova" in md
    assert md.index(".env exposto") < md.index("CSP ausente")  # ordenado por severidade


def test_markdown_table_cells_escape_pipes():
    md = to_markdown([Finding("c", Severity.LOW, "a | b")])
    assert "a \\| b" in md


def test_sarif_is_valid_shape_and_skips_info():
    doc = json.loads(to_sarif(_findings(), {"target": "https://ex.com"}))
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert [r["ruleId"] for r in run["results"]] == ["exposed.env", "headers.csp-missing"]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"exposed.env", "headers.csp-missing"}
    crit = run["results"][0]
    assert crit["level"] == "error" and crit["properties"]["security-severity"] == "9.5"
    assert crit["partialFingerprints"]["wvsFingerprint/v1"]
    assert crit["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://ex.com/"
    # ruleIndex aponta para a regra correta
    for r in run["results"]:
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]


def test_sarif_with_no_findings_is_still_valid():
    doc = json.loads(to_sarif([]))
    assert doc["runs"][0]["results"] == [] and doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_html_escapes_target_controlled_content():
    evil = Finding("x", Severity.LOW, "<script>alert(1)</script>", "<img src=x onerror=1>",
                   evidence="<svg onload=1>")
    out = to_html([evil], {"target": "<b>t</b>", "mode": "web"})
    for raw in ("<script>alert(1)", "<img src=x", "<b>t</b>", "<svg onload"):
        assert raw not in out
    assert "&lt;script&gt;" in out


def test_html_hides_info_on_request():
    assert "TLS 1.3" in to_html(_findings())
    assert "TLS 1.3" not in to_html(_findings(), show_info=False)


def test_summary_counts():
    assert summary(_findings()) == {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1}
