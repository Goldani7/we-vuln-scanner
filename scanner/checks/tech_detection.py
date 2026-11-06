"""Detecção de tecnologia exposta e CVEs conhecidas.

Vulnerabilidade: headers como Server/X-Powered-By revelam software e versão (fingerprinting),
ajudando o atacante a escolher exploits para CVEs publicadas daquela versão.
Exemplo: "Server: Apache/2.4.49" permite ao atacante tentar a CVE-2021-41773 (path traversal/RCE).
Ref.: OWASP WSTG-INFO-02 (Fingerprint Web Server); CWE-200 (Exposure of Sensitive Information).
Aqui as CVEs são consultadas na NVD (scanner/nvd.py); se falhar, usa-se uma tabela local mínima.
"""
import re

from .. import nvd
from ..finding import Finding, Severity

CHECK = "tech_detection"

# Fallback offline: tecnologia -> versão mínima considerada atualizada
MIN_VERSIONS = {"apache": "2.4.50", "nginx": "1.20.0", "php": "8.0"}
MAX_CVES_PER_TECH = 10

_TECH_RE = re.compile(r"([A-Za-z][\w.-]*)/(\d+(?:\.\d+)*)")


def _parse(version: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", version))


def severity_from_cvss(score) -> Severity:
    """Faixas CVSS v3: 9.0+ crítico, 7.0+ alto, 4.0+ médio, abaixo disso baixo."""
    if score is None:
        return Severity.LOW
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW


def _local_fallback(tech: str, version: str) -> list:
    minimum = MIN_VERSIONS.get(tech.lower())
    if minimum and _parse(version) < _parse(minimum):
        return [Finding(
            CHECK, Severity.MEDIUM, f"{tech} possivelmente desatualizado ({version})",
            f"Versão detectada {version} é anterior a {minimum} (tabela local).",
            f"Atualize {tech} para uma versão suportada.",
            {"tech": tech, "version": version, "minimum": minimum},
        )]
    return []


def _cve_findings(tech: str, version: str) -> list:
    try:
        cves = nvd.query_cves(tech, version)
    except nvd.NVDError as e:
        findings = [Finding(
            CHECK, Severity.INFO, "Consulta online à NVD falhou; usando tabela local",
            f"Não foi possível consultar a NVD para {tech} {version}: {e}",
            "Tente novamente mais tarde ou configure NVD_API_KEY.",
            {"tech": tech, "version": version},
        )]
        return findings + _local_fallback(tech, version)

    findings = []
    for cve in cves[:MAX_CVES_PER_TECH]:
        score = cve["score"]
        shown = f"CVSS {score}" if score is not None else "CVSS n/d"
        findings.append(Finding(
            CHECK, severity_from_cvss(score), f"{cve['id']} ({shown}) em {tech} {version}",
            f"{cve['description']} Detalhes: {cve['url']}",
            f"Atualize {tech} para uma versão sem esta vulnerabilidade.",
            {"cve": cve["id"], "cvss": score, "url": cve["url"], "tech": tech, "version": version},
            evidence=f"{tech}/{version} (via header) casou com {cve['id']} por busca de palavra-chave na NVD",
            references=[cve["url"]], confidence="low", rule_id="tech.cve",
        ))
    return findings


def check_tech_detection(response) -> list:
    findings = []
    for header in ("Server", "X-Powered-By"):
        value = response.headers.get(header)
        if not value:
            continue
        findings.append(Finding(
            CHECK, Severity.LOW, f"Header {header} expõe tecnologia",
            f"{header}: {value}",
            "Oculte ou genericize este header para reduzir fingerprinting.",
            {"header": header, "value": value},
            evidence=f"{header}: {value}", cwe="CWE-200", confidence="high", rule_id="tech.exposed-header",
        ))
        for tech, version in _TECH_RE.findall(value):
            findings.extend(_cve_findings(tech, version))
    if not findings:
        findings.append(Finding(CHECK, Severity.INFO, "Nenhuma tecnologia exposta nos headers"))
    return findings
