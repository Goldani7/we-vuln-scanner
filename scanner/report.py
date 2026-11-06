"""Geração de relatórios: texto, JSON versionado, Markdown, SARIF 2.1.0 e HTML."""
import html
import json
from datetime import datetime, timezone

from . import __version__
from .finding import Severity

SCHEMA_VERSION = "1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
# security-severity (0-10) é lido pelo GitHub Code Scanning para ordenar os alertas.
SARIF_SCORE = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
               Severity.LOW: "3.0", Severity.INFO: "0.0"}
SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "note", Severity.INFO: "note"}


def _sorted(findings):
    return sorted(findings, key=lambda f: (-f.severity.rank, f.check, f.title))


def summary(findings) -> dict:
    return {s.value: sum(1 for f in findings if f.severity is s) for s in ORDER}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------------------- texto

def to_text(findings, show_info: bool = True) -> str:
    lines = []
    for f in _sorted(findings):
        if f.severity is Severity.INFO and not show_info:
            continue
        lines.append(f"[{f.severity.label}] {f.title}")
        if f.detail:
            lines.append(f"    {f.detail}")
        if f.evidence:
            first = f.evidence.splitlines()
            lines.append(f"    Evidência: {first[0]}" + (" …" if len(first) > 1 else ""))
        if f.remediation:
            lines.append(f"    Correção: {f.remediation}")
    counts = summary(findings)
    lines.append("")
    lines.append("Resumo: " + ", ".join(f"{s.label}={counts[s.value]}" for s in ORDER))
    return "\n".join(lines)


# ----------------------------------------------------------------------------------------- JSON

def to_json(findings, meta=None) -> str:
    """Sem `meta`: lista de findings (formato da API). Com `meta`: relatório versionado."""
    items = [f.to_dict() for f in _sorted(findings)]
    if meta is None:
        return json.dumps(items, ensure_ascii=False, indent=2)
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "web-vuln-scanner", "version": __version__},
        **meta,
        "generated_at": _now(),
        "summary": summary(findings),
        "findings": items,
    }
    return json.dumps(report, ensure_ascii=False, indent=2)


# ------------------------------------------------------------------------------------- Markdown

def _md_escape_cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(findings, meta=None, show_info: bool = True) -> str:
    meta = meta or {}
    counts = summary(findings)
    out = [
        "# Relatório de segurança", "",
        f"- **Alvo:** `{meta.get('target', '-')}`",
        f"- **Modo:** {meta.get('mode', '-')}",
        f"- **Gerado em:** {_now()}",
        f"- **Ferramenta:** web-vuln-scanner {__version__}", "",
        "## Resumo", "",
        "| Severidade | Qtde |", "|---|---|",
    ]
    out += [f"| {s.label} | {counts[s.value]} |" for s in ORDER]
    actionable = [f for f in _sorted(findings) if f.severity is not Severity.INFO]
    if actionable:
        out += ["", "## Achados por prioridade", "", "| # | Severidade | Achado | Confiança |", "|---|---|---|---|"]
        out += [f"| {i} | {f.severity.label} | {_md_escape_cell(f.title)} | {f.confidence} |"
                for i, f in enumerate(actionable, 1)]
    out += ["", "## Detalhes"]
    n = 0
    for f in _sorted(findings):
        if f.severity is Severity.INFO and not show_info:
            continue
        n += 1
        out += ["", f"### {n}. [{f.severity.label}] {f.title}", "",
                f"`{f.rule}` · módulo `{f.check}` · confiança **{f.confidence}**"
                + (f" · {f.cwe}" if f.cwe else "") + f" · id `{f.fingerprint}`"]
        if f.detail:
            out += ["", f.detail]
        if f.evidence:
            out += ["", "**Evidência**", "", "```text", f.evidence.replace("```", "'''"), "```"]
        if f.remediation:
            out += ["", f"**Correção:** {f.remediation}"]
        if f.references:
            out += ["", "**Referências:** " + ", ".join(f"<{r}>" for r in f.references)]
    out += ["", "---", "",
            "*Use apenas em alvos autorizados. Esta ferramenta não substitui um pentest profissional.*"]
    return "\n".join(out)


# ----------------------------------------------------------------------------------------- SARIF

def to_sarif(findings, meta=None) -> str:
    """SARIF 2.1.0. Achados INFO (confirmações positivas) ficam de fora."""
    meta = meta or {}
    items = [f for f in _sorted(findings) if f.severity is not Severity.INFO]
    rules, rule_index = [], {}
    for f in items:
        if f.rule in rule_index:
            continue
        rule_index[f.rule] = len(rules)
        rule = {
            "id": f.rule,
            "name": f.rule.replace(".", "_").replace("-", "_"),
            "shortDescription": {"text": f.title[:120]},
            "help": {"text": f.remediation or f.detail or f.title},
            "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
            "properties": {"security-severity": SARIF_SCORE[f.severity],
                           "tags": ["security"] + ([f.cwe] if f.cwe else [])},
        }
        if f.references:
            rule["helpUri"] = f.references[0]
        rules.append(rule)

    results = []
    for f in items:
        text = f.title + (f" — {f.detail}" if f.detail else "")
        if f.evidence:
            text += f"\nEvidência: {f.evidence}"
        if f.remediation:
            text += f"\nCorreção: {f.remediation}"
        results.append({
            "ruleId": f.rule,
            "ruleIndex": rule_index[f.rule],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": text},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.target or meta.get("target", "")}}}],
            "partialFingerprints": {"wvsFingerprint/v1": f.fingerprint},
            "properties": {"severity": f.severity.value, "confidence": f.confidence,
                           "check": f.check, "security-severity": SARIF_SCORE[f.severity]},
        })
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "web-vuln-scanner", "version": __version__, "rules": rules}},
            "results": results,
            "invocations": [{"executionSuccessful": True, "endTimeUtc": _now()}],
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


# ------------------------------------------------------------------------------------------ HTML

_CSS = """
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1f2328}
h1{margin-bottom:.2rem}.meta{color:#656d76;margin-bottom:1.5rem}
.summary{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:1.5rem}
.badge{padding:.2rem .7rem;border-radius:1rem;color:#fff;font-weight:600;font-size:.85rem}
.critical{background:#82071e}.high{background:#cf222e}.medium{background:#bc4c00}
.low{background:#9a6700}.info{background:#57606a}
.finding{border:1px solid #d0d7de;border-left-width:5px;border-radius:6px;padding:.7rem 1rem;margin:.6rem 0}
.finding.critical{border-left-color:#82071e}.finding.high{border-left-color:#cf222e}
.finding.medium{border-left-color:#bc4c00}.finding.low{border-left-color:#9a6700}
.finding.info{border-left-color:#57606a}
.finding h3{margin:.2rem 0;font-size:1rem}.check{color:#656d76;font-size:.8rem}
pre{background:#f6f8fa;padding:.5rem;border-radius:4px;overflow-x:auto;font-size:.8rem}
.rec{color:#0969da;margin:.3rem 0 0}footer{margin-top:2rem;color:#656d76;font-size:.8rem}
"""


def to_html(findings, meta=None, show_info: bool = True) -> str:
    """Relatório HTML autocontido. Todo conteúdo vindo do alvo é escapado (anti-XSS)."""
    meta = meta or {}
    esc = html.escape
    counts = summary(findings)
    parts = [
        "<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">",
        "<title>Relatório de segurança</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>Relatório de segurança</h1>",
        f"<div class=\"meta\">Alvo: <strong>{esc(str(meta.get('target', '-')))}</strong> · "
        f"modo: {esc(str(meta.get('mode', '-')))} · gerado em {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}</div>",
        "<div class=\"summary\">",
    ]
    for s in ORDER:
        parts.append(f"<span class=\"badge {s.value}\">{s.label}: {counts[s.value]}</span>")
    parts.append("</div>")
    for f in _sorted(findings):
        if f.severity is Severity.INFO and not show_info:
            continue
        parts.append(f"<div class=\"finding {f.severity.value}\">")
        parts.append(f"<span class=\"check\">{esc(f.rule)} · {f.severity.label} · confiança {esc(f.confidence)}"
                     + (f" · {esc(f.cwe)}" if f.cwe else "") + "</span>")
        parts.append(f"<h3>{esc(f.title)}</h3>")
        if f.detail:
            parts.append(f"<div>{esc(f.detail)}</div>")
        if f.evidence:
            parts.append(f"<pre>{esc(f.evidence)}</pre>")
        if f.remediation:
            parts.append(f"<div class=\"rec\">Correção: {esc(f.remediation)}</div>")
        parts.append("</div>")
    parts.append("<footer>Use apenas em alvos autorizados. Esta ferramenta não substitui um pentest "
                 "profissional.</footer></body></html>")
    return "\n".join(parts)
