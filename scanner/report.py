import json

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


def to_json(findings) -> str:
    return json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2)
