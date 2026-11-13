"""Threat intelligence to prioritize CVEs: EPSS (FIRST) and CISA KEV.

Why: CVSS measures technical severity, not the likelihood of real-world use. In a pentest, what
matters first is what attackers actually exploit:
- CISA KEV (Known Exploited Vulnerabilities): CVEs with confirmed ACTIVE exploitation;
- EPSS (Exploit Prediction Scoring System): probability (0-1) of exploitation in the next 30 days.
Example: a CVE with CVSS 7.5 but EPSS 97% and present in the KEV should rank above a CVSS 9.8 with
EPSS 0.1%.

Both sources are public and free, and are cached for 24h. Network failures never take down the
scan: `enrich` returns whatever it got plus a list of warnings. Disable with WVS_THREAT_INTEL=0.
Ref.: https://www.cisa.gov/known-exploited-vulnerabilities-catalog ; https://www.first.org/epss/
"""
import json
import os
import time
from pathlib import Path

import httpx

from . import nvd
from .finding import Severity

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_TTL = 24 * 3600
EPSS_BATCH = 50  # the API accepts many CVEs per call; small batches avoid huge URLs
KEV_FIELDS = ("vendorProject", "product", "dateAdded", "dueDate", "knownRansomwareCampaignUse",
              "requiredAction")


class ThreatIntelError(Exception):
    """Failed to query EPSS or KEV (network, timeout, invalid response)."""


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
        pass  # the cache is only an optimization


def _fresh(ts) -> bool:
    return isinstance(ts, (int, float)) and time.time() - ts < CACHE_TTL


def _get_json(url: str, timeout: float, params=None):
    try:
        r = httpx.get(url, params=params, timeout=timeout, follow_redirects=True)
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise ThreatIntelError(f"{url}: {e}") from e


def kev_catalog(timeout: float = 15) -> dict:
    """{CVE-ID: {vendorProject, product, dateAdded, dueDate, ...}} from the CISA catalog."""
    cache = _load_cache()
    entry = cache.get("kev")
    if entry and _fresh(entry.get("ts")):
        return entry["data"]
    payload = _get_json(KEV_URL, timeout)
    try:
        data = {v["cveID"].upper(): {k: v.get(k, "") for k in KEV_FIELDS}
                for v in payload["vulnerabilities"]}
    except (KeyError, TypeError, AttributeError) as e:
        raise ThreatIntelError(f"KEV catalog has an unexpected format: {e}") from e
    cache["kev"] = {"ts": time.time(), "data": data}
    _save_cache(cache)
    return data


def epss_scores(cve_ids, timeout: float = 15) -> dict:
    """{CVE-ID: {"epss": float, "percentile": float}}. CVEs with no score are left out."""
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
            raise ThreatIntelError(f"EPSS response has an unexpected format: {e}") from e
    if missing:
        _save_cache(cache)
    return {c: {"epss": v["epss"], "percentile": v["percentile"]} for c, v in result.items()}


def enrich(cve_ids, timeout: float = 15):
    """Enriches CVEs with KEV and EPSS. Never raises: returns (info, warnings).

    info[CVE] = {"kev": dict|None, "epss": float|None, "percentile": float|None}
    """
    ids = sorted({c.upper() for c in cve_ids})
    if not ids or not enabled():
        return {}, []
    warnings, kev, epss = [], {}, {}
    try:
        kev = kev_catalog(timeout)
    except ThreatIntelError as e:
        warnings.append(f"CISA KEV unavailable: {e}")
    try:
        epss = epss_scores(ids, timeout)
    except ThreatIntelError as e:
        warnings.append(f"EPSS unavailable: {e}")
    info = {c: {"kev": kev.get(c), "epss": epss.get(c, {}).get("epss"),
                "percentile": epss.get(c, {}).get("percentile")} for c in ids}
    return info, warnings


def _at_least(current: Severity, floor: Severity) -> Severity:
    return current if current.rank >= floor.rank else floor


def prioritize(base: Severity, kev: bool, epss) -> Severity:
    """Adjusts the CVSS severity by the real exploitation risk (only ever goes up, never down).

    - KEV: confirmed exploitation → at least HIGH; CRITICAL if the CVSS was already HIGH or more.
    - EPSS >= 50% → at least HIGH; EPSS >= 10% → at least MEDIUM.
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
    """Priority order: KEV first, then EPSS, then CVSS (highest first)."""
    intel = intel or {}
    return (bool(intel.get("kev")), intel.get("epss") or 0.0, cvss or 0.0)
