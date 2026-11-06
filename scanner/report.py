"""Report generation: text, versioned JSON, Markdown, SARIF 2.1.0 and HTML."""
import html
import json
from datetime import datetime, timezone

from . import __version__
from .finding import Severity

SCHEMA_VERSION = "1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
# security-severity (0-10) is read by GitHub Code Scanning to rank alerts.
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


# ---------------------------------------------------------------------------------------- text

def to_text(findings, show_info: bool = True, meta=None) -> str:
    lines = []
    for f in _sorted(findings):
        if f.severity is Severity.INFO and not show_info:
            continue
        lines.append(f"[{f.severity.label}] {f.title}" + (" (NEW)" if f.status == "new" else ""))
        if f.detail:
            lines.append(f"    {f.detail}")
        if f.evidence:
            first = f.evidence.splitlines()
            lines.append(f"    Evidence: {first[0]}" + (" …" if len(first) > 1 else ""))
        if f.remediation:
            lines.append(f"    Fix: {f.remediation}")
    counts = summary(findings)
    lines.append("")
    base = (meta or {}).get("baseline")
    if base:
        lines.append(f"Baseline ({base['file']}): {base['new']} new, {base['unchanged']} unchanged, "
                     f"{base['resolved']} resolved")
    lines.append("Summary: " + ", ".join(f"{s.label}={counts[s.value]}" for s in ORDER))
    return "\n".join(lines)


# ----------------------------------------------------------------------------------------- JSON

def to_json(findings, meta=None) -> str:
    """Without `meta`: a plain list of findings (the API's format). With `meta`: a versioned report."""
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
        "# Security Report", "",
        f"- **Target:** `{meta.get('target', '-')}`",
        f"- **Mode:** {meta.get('mode', '-')}",
        f"- **Generated at:** {_now()}",
        f"- **Tool:** web-vuln-scanner {__version__}", "",
        "## Summary", "",
        "| Severity | Count |", "|---|---|",
    ]
    out += [f"| {s.label} | {counts[s.value]} |" for s in ORDER]
    base = meta.get("baseline")
    if base:
        out += ["", "## Baseline comparison", "",
                f"Baseline: `{base['file']}` · **{base['new']} new** · {base['unchanged']} unchanged · "
                f"{base['resolved']} resolved"]
        if base["resolved_findings"]:
            out += ["", "| Resolved | Severity |", "|---|---|"]
            out += [f"| {_md_escape_cell(r['title'])} | {r['severity']} |" for r in base["resolved_findings"]]
    actionable = [f for f in _sorted(findings) if f.severity is not Severity.INFO]
    if actionable:
        out += ["", "## Findings by priority", "",
               "| # | Severity | Finding | Exploitability | Confidence |", "|---|---|---|---|---|"]
        out += [f"| {i} | {f.severity.label} | {_md_escape_cell(f.title)} | {f.exploitability_label} | "
                f"{f.confidence} |" for i, f in enumerate(actionable, 1)]
    out += ["", "## Details"]
    n = 0
    for f in _sorted(findings):
        if f.severity is Severity.INFO and not show_info:
            continue
        n += 1
        out += ["", f"### {n}. [{f.severity.label}] {f.title}", "",
                f"`{f.rule}` · module `{f.check}` · confidence **{f.confidence}**"
                + (f" · {f.cwe}" if f.cwe else "") + f" · id `{f.fingerprint}`"
                + (" · **NEW**" if f.status == "new" else "")]
        if f.detail:
            out += ["", f.detail]
        if f.evidence:
            out += ["", "**Evidence**", "", "```text", f.evidence.replace("```", "'''"), "```"]
        if f.remediation:
            out += ["", f"**Fix:** {f.remediation}"]
        if f.references:
            out += ["", "**References:** " + ", ".join(f"<{r}>" for r in f.references)]
    out += ["", "---", "",
            "*Use only against authorized targets. This tool is not a substitute for a professional pentest.*"]
    return "\n".join(out)


# ----------------------------------------------------------------------------------------- SARIF

def to_sarif(findings, meta=None) -> str:
    """SARIF 2.1.0. INFO findings (positive confirmations) are left out."""
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
            text += f"\nEvidence: {f.evidence}"
        if f.remediation:
            text += f"\nFix: {f.remediation}"
        results.append({
            "ruleId": f.rule,
            "ruleIndex": rule_index[f.rule],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": text},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.target or meta.get("target", "")}}}],
            "partialFingerprints": {"wvsFingerprint/v1": f.fingerprint},
            **({"baselineState": f.status} if f.status else {}),
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
    """Self-contained HTML report. All target-controlled content is escaped (anti-XSS)."""
    meta = meta or {}
    esc = html.escape
    counts = summary(findings)
    parts = [
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<title>Security Report</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>Security Report</h1>",
        f"<div class=\"meta\">Target: <strong>{esc(str(meta.get('target', '-')))}</strong> · "
        f"mode: {esc(str(meta.get('mode', '-')))} · generated at {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}</div>",
        "<div class=\"summary\">",
    ]
    for s in ORDER:
        parts.append(f"<span class=\"badge {s.value}\">{s.label}: {counts[s.value]}</span>")
    parts.append("</div>")
    for f in _sorted(findings):
        if f.severity is Severity.INFO and not show_info:
            continue
        parts.append(f"<div class=\"finding {f.severity.value}\">")
        parts.append(f"<span class=\"check\">{esc(f.rule)} · {f.severity.label} · confidence {esc(f.confidence)}"
                     + (f" · {esc(f.cwe)}" if f.cwe else "") + (" · new" if f.status == "new" else "") + "</span>")
        parts.append(f"<h3>{esc(f.title)}</h3>")
        if f.detail:
            parts.append(f"<div>{esc(f.detail)}</div>")
        if f.evidence:
            parts.append(f"<pre>{esc(f.evidence)}</pre>")
        if f.remediation:
            parts.append(f"<div class=\"rec\">Fix: {esc(f.remediation)}</div>")
        parts.append("</div>")
    parts.append("<footer>Use only against authorized targets. This tool is not a substitute for a "
                 "professional pentest.</footer></body></html>")
    return "\n".join(parts)
