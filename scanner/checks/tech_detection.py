"""Exposed technology detection and known CVEs.

Vulnerability: headers like Server/X-Powered-By reveal software and version (fingerprinting),
helping the attacker pick exploits for published CVEs of that version.
Example: "Server: Apache/2.4.49" lets the attacker try CVE-2021-41773 (path traversal/RCE).
Ref.: OWASP WSTG-INFO-02 (Fingerprint Web Server); CWE-200 (Exposure of Sensitive Information).
CVEs here are looked up in the NVD (scanner/nvd.py); on failure, a minimal local table is used.
"""
import re

from .. import nvd, threatintel
from ..finding import Finding, Severity

CHECK = "tech_detection"

# Offline fallback: technology -> minimum version considered up to date
MIN_VERSIONS = {"apache": "2.4.50", "nginx": "1.20.0", "php": "8.0"}
MAX_CVES_PER_TECH = 10

_TECH_RE = re.compile(r"([A-Za-z][\w.-]*)/(\d+(?:\.\d+)*)")


def _parse(version: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", version))


def severity_from_cvss(score) -> Severity:
    """CVSS v3 bands: 9.0+ critical, 7.0+ high, 4.0+ medium, below that low."""
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
            CHECK, Severity.MEDIUM, f"{tech} possibly outdated ({version})",
            f"Detected version {version} is older than {minimum} (local table).",
            f"Update {tech} to a supported version.",
            {"tech": tech, "version": version, "minimum": minimum},
        )]
    return []


def _cve_findings(tech: str, version: str) -> list:
    try:
        cves = nvd.query_cves(tech, version)
    except nvd.NVDError as e:
        findings = [Finding(
            CHECK, Severity.INFO, "Online NVD lookup failed; using the local table",
            f"Could not query the NVD for {tech} {version}: {e}",
            "Try again later or set NVD_API_KEY.",
            {"tech": tech, "version": version},
        )]
        return findings + _local_fallback(tech, version)

    intel, warnings = threatintel.enrich([c["id"] for c in cves])
    ranked = sorted(cves, key=lambda c: threatintel.sort_key(c["score"], intel.get(c["id"].upper())),
                    reverse=True)

    findings = []
    for cve in ranked[:MAX_CVES_PER_TECH]:
        findings.append(_cve_finding(cve, tech, version, intel.get(cve["id"].upper()) or {}))
    if warnings:
        findings.append(Finding(
            CHECK, Severity.INFO, "EPSS/CISA KEV prioritization incomplete",
            "; ".join(warnings) + ". The severities below reflect CVSS only.",
            "Check connectivity, or set WVS_THREAT_INTEL=0 to run offline.",
            rule_id="tech.intel-unavailable"))
    return findings


def _pct(value: float) -> str:
    """Readable percentage: 0.99992 becomes '>99.9%' instead of rounding to 100%."""
    return ">99.9%" if value > 0.999 else f"{value:.1%}"


def _cve_finding(cve: dict, tech: str, version: str, intel: dict) -> Finding:
    score, kev, epss = cve["score"], intel.get("kev"), intel.get("epss")
    severity = threatintel.prioritize(severity_from_cvss(score), bool(kev), epss)

    badges = [f"CVSS {score}" if score is not None else "CVSS n/a"]
    if epss is not None:
        badges.append(f"EPSS {_pct(epss)}")
    if kev:
        badges.append("CISA KEV")

    evidence = [f"{tech}/{version} (from header) matched {cve['id']} via keyword search on the NVD"]
    if kev:
        evidence.append(
            f"CISA KEV: confirmed active exploitation (added {kev['dateAdded']}, due date "
            f"{kev['dueDate']}, ransomware use: {kev['knownRansomwareCampaignUse']}). "
            f"Product: {kev['vendorProject']} {kev['product']}")
    if epss is not None:
        evidence.append(f"EPSS: {_pct(epss)} chance of exploitation within 30 days "
                        f"(percentile {_pct(intel['percentile'])})")

    # The KEV confirms the CVE is exploited, but not that THIS instance is affected. If the KEV's
    # product matches the detected technology, the match is more reliable.
    product_match = bool(kev) and tech.lower() in f"{kev['vendorProject']} {kev['product']}".lower()
    remediation = f"Update {tech} to a version without this vulnerability."
    if kev:
        remediation = (f"TOP PRIORITY (actively exploited): {kev['requiredAction']} "
                       f"Confirm the installed version and update {tech}.")
    return Finding(
        CHECK, severity, f"{cve['id']} ({', '.join(badges)}) in {tech} {version}",
        f"{cve['description']} Details: {cve['url']}", remediation,
        {"cve": cve["id"], "cvss": score, "url": cve["url"], "tech": tech, "version": version,
         "kev": bool(kev), "epss": epss, "epss_percentile": intel.get("percentile")},
        evidence="\n".join(evidence), references=[cve["url"]] + (
            ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"] if kev else []),
        confidence="medium" if product_match else "low", rule_id="tech.cve")


def check_tech_detection(response) -> list:
    findings = []
    for header in ("Server", "X-Powered-By"):
        value = response.headers.get(header)
        if not value:
            continue
        findings.append(Finding(
            CHECK, Severity.LOW, f"Header {header} exposes technology",
            f"{header}: {value}",
            "Hide or genericize this header to reduce fingerprinting.",
            {"header": header, "value": value},
            evidence=f"{header}: {value}", cwe="CWE-200", confidence="high", rule_id="tech.exposed-header",
        ))
        for tech, version in _TECH_RE.findall(value):
            findings.extend(_cve_findings(tech, version))
    if not findings:
        findings.append(Finding(CHECK, Severity.INFO, "No technology exposed in the headers"))
    return findings
