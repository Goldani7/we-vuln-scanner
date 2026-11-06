"""Comparação entre execuções (--baseline).

Compara os achados atuais com um relatório JSON anterior (gerado com `-o x.json`) pelo `fingerprint`
(regra + título + alvo). Permite ao CI falhar só por achados NOVOS, em vez de repetir o mesmo alerta a
cada execução, e mostra o que foi corrigido.
Achados `info` (confirmações e contexto) não entram na comparação.
Atenção: o título faz parte do fingerprint. Se um achado muda de título (ex.: o CVSS ou o EPSS de um CVE
aparece no título), ele conta como "resolvido" + "novo": é uma mudança de risco que vale revisar.
"""
import dataclasses
import json
from dataclasses import dataclass, field

from .finding import Severity


class BaselineError(Exception):
    """Arquivo de baseline ausente, ilegível ou em formato inesperado."""


@dataclass
class Comparison:
    file: str = ""
    new: list = field(default_factory=list)
    unchanged: list = field(default_factory=list)
    resolved: list = field(default_factory=list)  # dicts do relatório anterior

    def summary(self) -> dict:
        return {
            "file": self.file, "new": len(self.new), "unchanged": len(self.unchanged),
            "resolved": len(self.resolved),
            "resolved_findings": [{"fingerprint": r["fingerprint"], "title": r.get("title", ""),
                                   "severity": r.get("severity", ""), "rule_id": r.get("rule_id", "")}
                                  for r in self.resolved],
        }


def load_baseline(path: str) -> dict:
    """{fingerprint: finding_dict} do relatório anterior (objeto versionado ou lista pura)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as e:
        raise BaselineError(f"não foi possível ler o baseline '{path}': {e.strerror or e}") from e
    except ValueError as e:
        raise BaselineError(f"o baseline '{path}' não é um JSON válido: {e}") from e

    items = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise BaselineError(f"o baseline '{path}' não tem uma lista de findings "
                            "(use um relatório gerado com -o relatorio.json)")
    out = {}
    for item in items:
        if not isinstance(item, dict) or not item.get("fingerprint"):
            raise BaselineError(f"o baseline '{path}' tem findings sem 'fingerprint': "
                                "foi gerado por uma versão antiga da ferramenta?")
        out[item["fingerprint"]] = item
    return out


def compare(findings, baseline: dict, path: str = "") -> Comparison:
    cmp = Comparison(file=path)
    current = set()
    for f in findings:
        if f.severity is Severity.INFO:
            continue
        current.add(f.fingerprint)
        (cmp.unchanged if f.fingerprint in baseline else cmp.new).append(f)
    cmp.resolved = [item for fp, item in baseline.items()
                    if fp not in current and item.get("severity") != Severity.INFO.value]
    return cmp


def annotate(findings, cmp: Comparison) -> list:
    """Cópias dos findings com `status` = "new" | "unchanged" (INFO fica sem status)."""
    new = {f.fingerprint for f in cmp.new}
    unchanged = {f.fingerprint for f in cmp.unchanged}
    return [dataclasses.replace(f, status="new" if f.fingerprint in new and f.severity is not Severity.INFO
                                else "unchanged" if f.fingerprint in unchanged and f.severity is not Severity.INFO
                                else "") for f in findings]
