import html
import json
from datetime import datetime, timezone

from .finding import Severity

LABELS = {
    Severity.HIGH: "ALTO",
    Severity.MEDIUM: "MÉDIO",
    Severity.LOW: "BAIXO",
    Severity.INFO: "INFO",
}


def to_text(findings, show_info: bool = True) -> str:
    items = sorted(findings, key=lambda f: f.severity.rank, reverse=True)
    lines = []
    for f in items:
        if f.severity is Severity.INFO and not show_info:
            continue
        lines.append(f"[{LABELS[f.severity]}] {f.title}")
        if f.detail:
            lines.append(f"    {f.detail}")
        if f.recommendation:
            lines.append(f"    Recomendação: {f.recommendation}")
    counts = {s: sum(1 for f in findings if f.severity is s) for s in LABELS}
    lines.append("")
    lines.append(
        "Resumo: " + ", ".join(f"{LABELS[s]}={counts[s]}" for s in LABELS)
    )
    return "\n".join(lines)


def summary(findings) -> dict:
    return {s.value: sum(1 for f in findings if f.severity is s) for s in LABELS}


def to_json(findings, meta=None) -> str:
    """Sem `meta`: lista de findings (formato da API). Com `meta`: relatório completo."""
    items = [f.to_dict() for f in findings]
    if meta is None:
        return json.dumps(items, ensure_ascii=False, indent=2)
    report = {
        **meta,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary(findings),
        "findings": items,
    }
    return json.dumps(report, ensure_ascii=False, indent=2)


_CSS = """
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1f2328}
h1{margin-bottom:.2rem}.meta{color:#656d76;margin-bottom:1.5rem}
.summary{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:1.5rem}
.badge{padding:.2rem .7rem;border-radius:1rem;color:#fff;font-weight:600;font-size:.85rem}
.alto{background:#cf222e}.médio{background:#bc4c00}.baixo{background:#9a6700}.info{background:#57606a}
.finding{border:1px solid #d0d7de;border-left-width:5px;border-radius:6px;padding:.7rem 1rem;margin:.6rem 0}
.finding.alto{border-left-color:#cf222e}.finding.médio{border-left-color:#bc4c00}
.finding.baixo{border-left-color:#9a6700}.finding.info{border-left-color:#57606a}
.finding h3{margin:.2rem 0;font-size:1rem}.check{color:#656d76;font-size:.8rem}
.rec{color:#0969da;margin:.3rem 0 0}footer{margin-top:2rem;color:#656d76;font-size:.8rem}
"""


def to_html(findings, meta=None, show_info: bool = True) -> str:
    """Relatório HTML autocontido. Todo conteúdo vindo do alvo é escapado (anti-XSS)."""
    meta = meta or {}
    esc = html.escape
    counts = summary(findings)
    items = sorted(findings, key=lambda f: f.severity.rank, reverse=True)
    parts = [
        "<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">",
        "<title>Relatório de segurança</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>Relatório de segurança</h1>",
        f"<div class=\"meta\">Alvo: <strong>{esc(str(meta.get('target', '-')))}</strong> · "
        f"modo: {esc(str(meta.get('mode', '-')))} · "
        f"gerado em {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}</div>",
        "<div class=\"summary\">",
    ]
    for sev, label in LABELS.items():
        parts.append(f"<span class=\"badge {sev.value}\">{label}: {counts[sev.value]}</span>")
    parts.append("</div>")
    for f in items:
        if f.severity is Severity.INFO and not show_info:
            continue
        parts.append(f"<div class=\"finding {f.severity.value}\">")
        parts.append(f"<span class=\"check\">{esc(f.check)} · {LABELS[f.severity]}</span>")
        parts.append(f"<h3>{esc(f.title)}</h3>")
        if f.detail:
            parts.append(f"<div>{esc(f.detail)}</div>")
        if f.recommendation:
            parts.append(f"<div class=\"rec\">Recomendação: {esc(f.recommendation)}</div>")
        parts.append("</div>")
    parts.append("<footer>Use apenas em alvos autorizados. Esta ferramenta não substitui um pentest "
                 "profissional.</footer></body></html>")
    return "\n".join(parts)
