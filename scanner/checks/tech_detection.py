import re

from ..finding import Finding, Severity

CHECK = "tech_detection"

# tecnologia -> versão mínima considerada atualizada
MIN_VERSIONS = {"apache": "2.4.50", "nginx": "1.20.0", "php": "8.0"}


def _parse(version: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", version))


def _analyze(header: str, value: str) -> list:
    findings = [Finding(
        CHECK, Severity.LOW, f"Header {header} expõe tecnologia",
        f"{header}: {value}",
        "Oculte ou genericize este header para reduzir fingerprinting.",
        {"header": header, "value": value},
    )]
    for tech, minimum in MIN_VERSIONS.items():
        m = re.search(rf"{tech}/?\s*(\d+(?:\.\d+)*)", value, re.IGNORECASE)
        if m and _parse(m.group(1)) < _parse(minimum):
            findings.append(Finding(
                CHECK, Severity.MEDIUM, f"{tech} possivelmente desatualizado ({m.group(1)})",
                f"Versão detectada {m.group(1)} é anterior a {minimum}.",
                f"Atualize {tech} para uma versão suportada.",
                {"tech": tech, "version": m.group(1), "minimum": minimum},
            ))
    return findings


def check_tech_detection(response) -> list:
    findings = []
    for header in ("Server", "X-Powered-By"):
        value = response.headers.get(header)
        if value:
            findings.extend(_analyze(header, value))
    if not findings:
        findings.append(Finding(CHECK, Severity.INFO, "Nenhuma tecnologia exposta nos headers"))
    return findings
