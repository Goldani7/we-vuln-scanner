import json

from scanner.finding import Finding, Severity
from scanner.report import summary, to_html, to_json


def _findings():
    return [
        Finding("headers", Severity.HIGH, "CSP ausente", "detalhe", "corrija"),
        Finding("tls", Severity.INFO, "TLS 1.3"),
    ]


def test_json_without_meta_is_a_list():
    assert isinstance(json.loads(to_json(_findings())), list)


def test_json_with_meta_has_summary_and_findings():
    data = json.loads(to_json(_findings(), {"target": "ex.com", "mode": "full"}))
    assert data["target"] == "ex.com"
    assert data["summary"]["alto"] == 1 and data["summary"]["info"] == 1
    assert len(data["findings"]) == 2 and data["generated_at"]


def test_html_escapes_target_controlled_content():
    evil = Finding("x", Severity.LOW, "<script>alert(1)</script>", "<img src=x onerror=1>")
    out = to_html([evil], {"target": "<b>t</b>", "mode": "web"})
    assert "<script>alert(1)" not in out and "<img src=x" not in out and "<b>t</b>" not in out
    assert "&lt;script&gt;" in out


def test_html_hides_info_on_request():
    assert "TLS 1.3" in to_html(_findings())
    assert "TLS 1.3" not in to_html(_findings(), show_info=False)


def test_summary_counts():
    assert summary(_findings()) == {"info": 1, "baixo": 0, "médio": 0, "alto": 1}
