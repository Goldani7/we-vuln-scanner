"""Inteligência de ameaças para priorizar CVEs: EPSS (FIRST) e CISA KEV.

Por quê: o CVSS mede a gravidade técnica, não a chance de uso real. Num pentest o que importa
primeiro é o que atacantes de fato exploram:
- CISA KEV (Known Exploited Vulnerabilities): CVEs com exploração ATIVA confirmada;
- EPSS (Exploit Prediction Scoring System): probabilidade (0-1) de exploração nos próximos 30 dias.
Exemplo: um CVE com CVSS 7,5 mas EPSS 97% e presente na KEV deve vir antes de um CVSS 9,8 com EPSS 0,1%.

Ambas as fontes são públicas e gratuitas, e ficam em cache por 24h. Falhas de rede nunca derrubam o
scan: `enrich` devolve o que conseguiu e uma lista de avisos. Desative com WVS_THREAT_INTEL=0.
Ref.: https://www.cisa.gov/known-exploited-vulnerabilities-catalog ; https://www.first.org/epss/
"""
import json
import os
import time
from pathlib import Path

import requests

from . import nvd
from .finding import Severity

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_TTL = 24 * 3600
EPSS_BATCH = 50  # a API aceita muitos CVEs por chamada; lotes pequenos evitam URLs enormes
KEV_FIELDS = ("vendorProject", "product", "dateAdded", "dueDate", "knownRansomwareCampaignUse",
              "requiredAction")


class ThreatIntelError(Exception):
    """Falha ao consultar EPSS ou KEV (rede, timeout, resposta inválida)."""


def enabled() -> bool:
    return os.environ.get("WVS_THREAT_INTEL", "1").strip().lower() not in ("0", "false", "no", "off")


def _cache_file() -> Path:
    return nvd._cache_path().with_name("threat_intel_cache.json")


def _load_cache() -> dict:
    try:
        return json.loads(_cache_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        path = _cache_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass  # cache é só otimização


def _fresh(ts) -> bool:
    return isinstance(ts, (int, float)) and time.time() - ts < CACHE_TTL


def _get_json(url: str, timeout: float, params=None):
    try:
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError) as e:
        raise ThreatIntelError(f"{url}: {e}") from e


def kev_catalog(timeout: float = 15) -> dict:
    """{CVE-ID: {vendorProject, product, dateAdded, dueDate, ...}} do catálogo da CISA."""
    cache = _load_cache()
    entry = cache.get("kev")
    if entry and _fresh(entry.get("ts")):
        return entry["data"]
    payload = _get_json(KEV_URL, timeout)
    try:
        data = {v["cveID"].upper(): {k: v.get(k, "") for k in KEV_FIELDS}
                for v in payload["vulnerabilities"]}
    except (KeyError, TypeError, AttributeError) as e:
        raise ThreatIntelError(f"catálogo KEV com formato inesperado: {e}") from e
    cache["kev"] = {"ts": time.time(), "data": data}
    _save_cache(cache)
    return data


def epss_scores(cve_ids, timeout: float = 15) -> dict:
    """{CVE-ID: {"epss": float, "percentile": float}}. CVEs sem score ficam fora do resultado."""
    ids = sorted({c.upper() for c in cve_ids})
    cache = _load_cache()
    store = cache.setdefault("epss", {})
    result = {c: store[c] for c in ids if c in store and _fresh(store[c].get("ts"))}
    missing = [c for c in ids if c not in result]
    for i in range(0, len(missing), EPSS_BATCH):
        batch = missing[i:i + EPSS_BATCH]
        payload = _get_json(EPSS_URL, timeout, params={"cve": ",".join(batch)})
        try:
            for row in payload.get("data", []):
                result[row["cve"].upper()] = store[row["cve"].upper()] = {
                    "epss": float(row["epss"]), "percentile": float(row["percentile"]), "ts": time.time()}
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise ThreatIntelError(f"resposta EPSS com formato inesperado: {e}") from e
    if missing:
        _save_cache(cache)
    return {c: {"epss": v["epss"], "percentile": v["percentile"]} for c, v in result.items()}


def enrich(cve_ids, timeout: float = 15):
    """Enriquece CVEs com KEV e EPSS. Nunca levanta: devolve (info, avisos).

    info[CVE] = {"kev": dict|None, "epss": float|None, "percentile": float|None}
    """
    ids = sorted({c.upper() for c in cve_ids})
    if not ids or not enabled():
        return {}, []
    warnings, kev, epss = [], {}, {}
    try:
        kev = kev_catalog(timeout)
    except ThreatIntelError as e:
        warnings.append(f"CISA KEV indisponível: {e}")
    try:
        epss = epss_scores(ids, timeout)
    except ThreatIntelError as e:
        warnings.append(f"EPSS indisponível: {e}")
    info = {c: {"kev": kev.get(c), "epss": epss.get(c, {}).get("epss"),
                "percentile": epss.get(c, {}).get("percentile")} for c in ids}
    return info, warnings


def _at_least(current: Severity, floor: Severity) -> Severity:
    return current if current.rank >= floor.rank else floor


def prioritize(base: Severity, kev: bool, epss) -> Severity:
    """Ajusta a severidade do CVSS pelo risco real de exploração (só sobe, nunca desce).

    - KEV: exploração confirmada → no mínimo ALTO; CRITICAL se o CVSS já era ALTO ou mais.
    - EPSS ≥ 50% → no mínimo ALTO; EPSS ≥ 10% → no mínimo MÉDIO.
    """
    if kev:
        return Severity.CRITICAL if base.rank >= Severity.HIGH.rank else _at_least(base, Severity.HIGH)
    if epss is not None:
        if epss >= 0.5:
            return _at_least(base, Severity.HIGH)
        if epss >= 0.1:
            return _at_least(base, Severity.MEDIUM)
    return base


def sort_key(cvss, intel) -> tuple:
    """Ordem de prioridade: KEV primeiro, depois EPSS, depois CVSS (maior primeiro)."""
    intel = intel or {}
    return (bool(intel.get("kev")), intel.get("epss") or 0.0, cvss or 0.0)
