"""Minimal NVD API 2.0 (NIST) client with an on-disk cache.

Looks up CVEs by CPE (`virtualMatchString`) when the technology is known: the NVD itself decides
whether the version falls inside each CVE's affected range, which is far more precise than the
free-text `keywordSearch` (that one matches any CVE merely *mentioning* "nginx 1.18"). Unknown
technologies fall back to keyword search, flagged as `match="keyword"` so callers can lower their
confidence. NVD_API_KEY is optional: the API works
without it, just with a lower limit (~5 req/30s; ~50 req/30s with a key).
Free key: https://nvd.nist.gov/developers/request-an-api-key
"""
import json
import os
import time
from pathlib import Path

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = 7 * 24 * 3600  # 7 days
MAX_RESULTS = 20

# Server/X-Powered-By product token -> candidate (vendor, product) pairs in the CPE dictionary.
# More than one pair when the vendor changed over time (nginx moved to F5).
CPE_MAP = {
    "apache": [("apache", "http_server")],
    "nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "php": [("php", "php")],
    "openssl": [("openssl", "openssl")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "tomcat": [("apache", "tomcat")],
    "jetty": [("eclipse", "jetty")],
    "express": [("expressjs", "express")],
    "microsoft-iis": [("microsoft", "internet_information_services")],
    "litespeed": [("litespeedtech", "litespeed_web_server")],
    "openresty": [("openresty", "openresty")],
    "caddy": [("caddyserver", "caddy")],
    "gunicorn": [("gunicorn", "gunicorn")],
    "node.js": [("nodejs", "node.js")],
    "wordpress": [("wordpress", "wordpress")],
    "drupal": [("drupal", "drupal")],
}


class NVDError(Exception):
    """Failed to query the NVD (network, rate limit, timeout, invalid response)."""


def _cache_path() -> Path:
    override = os.environ.get("NVD_CACHE_PATH")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "web-vuln-scanner" / "nvd_cache.json"


def _load_cache() -> dict:
    try:
        return json.loads(_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        path = _cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass  # the cache is only an optimization; never break the scan over it


def _base_score(cve: dict):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            return metrics[key][0].get("cvssData", {}).get("baseScore")
    return None


def parse_cves(payload: dict, match: str = "keyword") -> list:
    """Converts the NVD response into [{id, score, description, url, match}], highest score first."""
    results = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        )
        results.append({
            "id": cve_id,
            "score": _base_score(cve),
            "description": desc[:200] + ("…" if len(desc) > 200 else ""),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "match": match,
        })
    results.sort(key=lambda c: c["score"] or 0, reverse=True)
    return results


def _fetch(params: dict, headers: dict, timeout: float) -> dict:
    try:
        r = httpx.get(NVD_URL, params=params, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise NVDError(str(e)) from e


def query_cves(tech: str, version: str, timeout: int = 8) -> list:
    """CVEs for `tech` `version`. Each result carries match="cpe" (precise) or "keyword" (fuzzy)."""
    key = f"{tech.lower()}|{version}"
    cache = _load_cache()
    entry = cache.get(key)
    if entry and time.time() - entry["ts"] < CACHE_TTL:
        return entry["cves"]

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    candidates = CPE_MAP.get(tech.lower())
    if candidates:
        merged = {}
        for vendor, product in candidates:
            payload = _fetch({"virtualMatchString": f"cpe:2.3:a:{vendor}:{product}:{version}",
                              "resultsPerPage": MAX_RESULTS}, headers, timeout)
            for cve in parse_cves(payload, match="cpe"):
                merged.setdefault(cve["id"], cve)
        cves = sorted(merged.values(), key=lambda c: c["score"] or 0, reverse=True)
    else:
        payload = _fetch({"keywordSearch": f"{tech} {version}", "resultsPerPage": MAX_RESULTS},
                         headers, timeout)
        cves = parse_cves(payload, match="keyword")

    cache[key] = {"ts": time.time(), "cves": cves}
    _save_cache(cache)
    return cves
