"""Cliente mínimo da NVD API 2.0 (NIST) com cache em disco.

Consulta CVEs por palavra-chave (tecnologia + versão). A NVD_API_KEY é opcional:
sem ela a API funciona, mas com limite menor (~5 req/30s; com key, ~50 req/30s).
Chave gratuita: https://nvd.nist.gov/developers/request-an-api-key
"""
import json
import os
import time
from pathlib import Path

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = 7 * 24 * 3600  # 7 dias
MAX_RESULTS = 20


class NVDError(Exception):
    """Falha ao consultar a NVD (rede, rate limit, timeout, resposta inválida)."""


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
        pass  # cache é só otimização; nunca quebrar o scan por isso


def _base_score(cve: dict):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            return metrics[key][0].get("cvssData", {}).get("baseScore")
    return None


def parse_cves(payload: dict) -> list:
    """Converte a resposta da NVD em [{id, score, description, url}], maior score primeiro."""
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
        })
    results.sort(key=lambda c: c["score"] or 0, reverse=True)
    return results


def query_cves(tech: str, version: str, timeout: int = 8) -> list:
    key = f"{tech.lower()}|{version}"
    cache = _load_cache()
    entry = cache.get(key)
    if entry and time.time() - entry["ts"] < CACHE_TTL:
        return entry["cves"]

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    try:
        r = requests.get(
            NVD_URL,
            params={"keywordSearch": f"{tech} {version}", "resultsPerPage": MAX_RESULTS},
            headers=headers,
            timeout=timeout,
        )
        r.raise_for_status()
        cves = parse_cves(r.json())
    except (requests.RequestException, ValueError) as e:
        raise NVDError(str(e)) from e

    cache[key] = {"ts": time.time(), "cves": cves}
    _save_cache(cache)
    return cves
