from unittest.mock import patch

import pytest
import requests

from scanner import threatintel as ti
from scanner.finding import Severity

KEV_PAYLOAD = {"vulnerabilities": [
    {"cveID": "CVE-2021-41773", "vendorProject": "Apache", "product": "HTTP Server",
     "dateAdded": "2021-11-03", "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Unknown",
     "requiredAction": "Apply updates.", "notes": "ignorado"},
]}


class Resp:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


def epss_payload(**scores):
    return {"data": [{"cve": c, "epss": str(s), "percentile": "0.99", "date": "2026-11-06"}
                     for c, s in scores.items()]}


@pytest.fixture(autouse=True)
def _cache(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_CACHE_PATH", str(tmp_path / "nvd.json"))
    monkeypatch.delenv("WVS_THREAT_INTEL", raising=False)


def test_kev_catalog_parses_keeps_only_known_fields_and_caches():
    with patch("scanner.threatintel.requests.get", return_value=Resp(KEV_PAYLOAD)) as get:
        first, second = ti.kev_catalog(), ti.kev_catalog()
    assert get.call_count == 1 and first == second
    assert first["CVE-2021-41773"]["dueDate"] == "2021-11-17" and "notes" not in first["CVE-2021-41773"]


def test_epss_scores_batches_and_caches():
    ids = [f"CVE-2020-{i:04d}" for i in range(120)]

    def fake_get(url, params=None, timeout=None):
        return Resp(epss_payload(**{c: 0.25 for c in params["cve"].split(",")}))
    with patch("scanner.threatintel.requests.get", side_effect=fake_get) as get:
        scores = ti.epss_scores(ids)
        assert get.call_count == 3  # 50 + 50 + 20
        ti.epss_scores(ids)
        assert get.call_count == 3  # segunda chamada vem do cache
    assert scores["CVE-2020-0000"] == {"epss": 0.25, "percentile": 0.99} and len(scores) == 120


def test_epss_ids_are_case_insensitive_and_deduplicated():
    with patch("scanner.threatintel.requests.get", return_value=Resp(epss_payload(**{"CVE-2021-1": 0.1}))) as get:
        assert "CVE-2021-1" in ti.epss_scores(["cve-2021-1", "CVE-2021-1"])
    assert get.call_args.kwargs["params"]["cve"] == "CVE-2021-1"


def test_enrich_combines_sources():
    def fake_get(url, params=None, timeout=None):
        return Resp(KEV_PAYLOAD if url == ti.KEV_URL else epss_payload(**{"CVE-2021-41773": 0.99992}))
    with patch("scanner.threatintel.requests.get", side_effect=fake_get):
        info, warnings = ti.enrich(["CVE-2021-41773", "CVE-2099-0001"])
    assert warnings == []
    assert info["CVE-2021-41773"]["kev"]["vendorProject"] == "Apache"
    assert info["CVE-2021-41773"]["epss"] == pytest.approx(0.99992)
    assert info["CVE-2099-0001"] == {"kev": None, "epss": None, "percentile": None}


def test_enrich_survives_one_source_failing():
    def fake_get(url, params=None, timeout=None):
        if url == ti.KEV_URL:
            raise requests.Timeout("slow")
        return Resp(epss_payload(**{"CVE-2021-1": 0.7}))
    with patch("scanner.threatintel.requests.get", side_effect=fake_get):
        info, warnings = ti.enrich(["CVE-2021-1"])
    assert info["CVE-2021-1"]["epss"] == 0.7 and info["CVE-2021-1"]["kev"] is None
    assert len(warnings) == 1 and warnings[0].startswith("CISA KEV indisponível")


def test_enrich_never_raises_when_everything_fails():
    with patch("scanner.threatintel.requests.get", side_effect=requests.ConnectionError("down")):
        info, warnings = ti.enrich(["CVE-2021-1"])
    assert len(warnings) == 2 and info["CVE-2021-1"]["epss"] is None


def test_malformed_payloads_are_errors_not_crashes():
    with patch("scanner.threatintel.requests.get", return_value=Resp({"unexpected": 1})):
        _, warnings = ti.enrich(["CVE-2021-1"])
    assert len(warnings) == 1  # KEV malformado; EPSS sem 'data' é simplesmente vazio


def test_disabled_by_env_makes_no_requests(monkeypatch):
    monkeypatch.setenv("WVS_THREAT_INTEL", "0")
    with patch("scanner.threatintel.requests.get") as get:
        assert ti.enrich(["CVE-2021-1"]) == ({}, [])
    assert not get.called


@pytest.mark.parametrize("base,kev,epss,expected", [
    (Severity.MEDIUM, True, None, Severity.HIGH),
    (Severity.LOW, True, 0.0, Severity.HIGH),
    (Severity.HIGH, True, None, Severity.CRITICAL),
    (Severity.CRITICAL, True, None, Severity.CRITICAL),
    (Severity.LOW, False, 0.6, Severity.HIGH),
    (Severity.LOW, False, 0.15, Severity.MEDIUM),
    (Severity.MEDIUM, False, 0.15, Severity.MEDIUM),
    (Severity.CRITICAL, False, 0.001, Severity.CRITICAL),  # EPSS baixo nunca rebaixa
    (Severity.HIGH, False, None, Severity.HIGH),
])
def test_prioritize(base, kev, epss, expected):
    assert ti.prioritize(base, kev, epss) is expected


def test_sort_key_orders_kev_then_epss_then_cvss():
    rows = [("a", 9.8, {"epss": 0.001}), ("b", 5.0, {"kev": {"x": 1}, "epss": 0.2}),
            ("c", 7.0, {"epss": 0.9}), ("d", 9.8, None)]
    order = [r[0] for r in sorted(rows, key=lambda r: ti.sort_key(r[1], r[2]), reverse=True)]
    assert order == ["b", "c", "a", "d"]
