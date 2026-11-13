from unittest.mock import patch

import httpx
import pytest

from scanner import nvd
from scanner.checks.tech_detection import check_tech_detection, severity_from_cvss
from scanner.finding import Severity


@pytest.fixture(autouse=True)
def _no_threat_intel_network():
    with patch("scanner.checks.tech_detection.threatintel.enrich", return_value=({}, [])) as m:
        yield m


class FakeResponse:
    def __init__(self, headers):
        self.headers = headers


NVD_PAYLOAD = {"vulnerabilities": [
    {"cve": {"id": "CVE-2021-0001",
             "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Bug grave"}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}},
    {"cve": {"id": "CVE-2021-0002",
             "descriptions": [{"lang": "en", "value": "Medium bug"}],
             "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}}},
    {"cve": {"id": "CVE-2021-0003",
             "descriptions": [{"lang": "en", "value": "Bug leve"}], "metrics": {}}},
]}


@pytest.mark.parametrize("score,sev", [
    (9.8, Severity.CRITICAL), (9.0, Severity.CRITICAL), (8.9, Severity.HIGH), (7.0, Severity.HIGH),
    (6.9, Severity.MEDIUM),
    (4.0, Severity.MEDIUM), (3.9, Severity.LOW), (None, Severity.LOW),
])
def test_severity_mapping(score, sev):
    assert severity_from_cvss(score) is sev


def test_parse_cves():
    cves = nvd.parse_cves(NVD_PAYLOAD)
    assert [c["id"] for c in cves] == ["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"]
    assert cves[0]["description"] == "Bug grave"
    assert cves[0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-0001"
    assert cves[2]["score"] is None


def test_cve_findings_from_nvd():
    cves = nvd.parse_cves(NVD_PAYLOAD)
    with patch("scanner.checks.tech_detection.nvd.query_cves", return_value=cves) as q:
        findings = check_tech_detection(FakeResponse({"Server": "nginx/1.18.0 (Ubuntu)"}))
    q.assert_called_once_with("nginx", "1.18.0")
    cve_f = [f for f in findings if "cve" in f.metadata]
    assert [f.severity for f in cve_f] == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]
    assert "CVE-2021-0001" in cve_f[0].title
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-0001" in cve_f[0].detail
    assert cve_f[0].confidence == "low" and "nginx/1.18.0" in cve_f[0].evidence


def test_graceful_fallback_when_nvd_fails():
    with patch("scanner.checks.tech_detection.nvd.query_cves",
               side_effect=nvd.NVDError("timeout")):
        findings = check_tech_detection(FakeResponse({"Server": "nginx/1.18.0"}))
    sevs = [f.severity for f in findings]
    assert Severity.INFO in sevs  # aviso de falha na consulta online
    assert Severity.MEDIUM in sevs  # tabela local: nginx 1.18.0 < 1.20.0


def test_no_headers_is_info():
    findings = check_tech_detection(FakeResponse({}))
    assert len(findings) == 1 and findings[0].severity is Severity.INFO


def test_query_cves_uses_cache_and_api_key(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("NVD_API_KEY", "secret")

    class Resp:
        def raise_for_status(self): pass
        def json(self): return NVD_PAYLOAD

    with patch("scanner.nvd.httpx.get", return_value=Resp()) as get:
        first = nvd.query_cves("nginx", "1.18.0")
        second = nvd.query_cves("nginx", "1.18.0")
    assert first == second
    assert get.call_count == 2  # f5 + nginx vendors; the second query_cves() came from the cache
    assert get.call_args.kwargs["headers"] == {"apiKey": "secret"}
    # nginx is in the CPE map: precise virtualMatchString, one query per candidate vendor
    assert get.call_args_list[0].kwargs["params"]["virtualMatchString"] == "cpe:2.3:a:f5:nginx:1.18.0"


def test_query_cves_network_error_raises_nvd_error(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_CACHE_PATH", str(tmp_path / "cache.json"))
    with patch("scanner.nvd.httpx.get", side_effect=httpx.TimeoutException("t")):
        with pytest.raises(nvd.NVDError):
            nvd.query_cves("nginx", "1.18.0")


def _cves():
    return nvd.parse_cves(NVD_PAYLOAD)


KEV_ENTRY = {"vendorProject": "Nginx", "product": "nginx", "dateAdded": "2021-11-03",
             "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Known",
             "requiredAction": "Apply updates per vendor instructions."}


def _scan_with_intel(intel, warnings=()):
    with patch("scanner.checks.tech_detection.nvd.query_cves", return_value=_cves()), \
         patch("scanner.checks.tech_detection.threatintel.enrich", return_value=(intel, list(warnings))):
        return check_tech_detection(FakeResponse({"Server": "nginx/1.18.0"}))


def test_kev_cve_becomes_critical_with_evidence_and_urgent_remediation():
    # CVE-2021-0002 has CVSS 5.0 (medium), but is in the KEV with high EPSS
    intel = {"CVE-2021-0002": {"kev": KEV_ENTRY, "epss": 0.97, "percentile": 0.999}}
    f = next(x for x in _scan_with_intel(intel) if x.metadata.get("cve") == "CVE-2021-0002")
    assert f.severity is Severity.HIGH  # medium CVSS + KEV => at least HIGH
    assert "CISA KEV" in f.title and "EPSS 97.0%" in f.title
    assert "confirmed active exploitation" in f.evidence and "ransomware use: Known" in f.evidence
    assert f.remediation.startswith("TOP PRIORITY")
    assert f.metadata["kev"] is True and f.metadata["epss"] == 0.97
    assert f.confidence == "medium"  # produto da KEV (nginx) bate com a tecnologia detectada


def test_kev_on_high_cvss_is_critical():
    intel = {"CVE-2021-0001": {"kev": KEV_ENTRY, "epss": 0.5, "percentile": 0.9}}
    f = next(x for x in _scan_with_intel(intel) if x.metadata.get("cve") == "CVE-2021-0001")
    assert f.severity is Severity.CRITICAL


def test_kev_for_unrelated_product_keeps_low_confidence():
    other = {**KEV_ENTRY, "vendorProject": "Apple", "product": "iOS"}
    f = next(x for x in _scan_with_intel({"CVE-2021-0002": {"kev": other, "epss": 0.1, "percentile": 0.5}})
             if x.metadata.get("cve") == "CVE-2021-0002")
    assert f.confidence == "low"


def test_findings_are_ordered_by_exploitation_risk_not_cvss():
    intel = {"CVE-2021-0003": {"kev": KEV_ENTRY, "epss": 0.9, "percentile": 0.99}}  # CVSS n/d
    order = [x.metadata["cve"] for x in _scan_with_intel(intel) if "cve" in x.metadata]
    assert order[0] == "CVE-2021-0003" and order[1:] == ["CVE-2021-0001", "CVE-2021-0002"]


def test_intel_failure_is_reported_and_cvss_severity_is_kept():
    findings = _scan_with_intel({}, ["EPSS unavailable: timeout"])
    notice = [f for f in findings if f.rule == "tech.intel-unavailable"]
    assert notice and "EPSS unavailable" in notice[0].detail
    assert [f.severity for f in findings if "cve" in f.metadata] == [
        Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_unknown_tech_falls_back_to_keyword_and_lowers_confidence(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_CACHE_PATH", str(tmp_path / "cache.json"))

    class Resp:
        def raise_for_status(self): pass
        def json(self): return NVD_PAYLOAD

    with patch("scanner.nvd.httpx.get", return_value=Resp()) as get:
        cves = nvd.query_cves("obscure-server", "1.0")
    assert get.call_args.kwargs["params"]["keywordSearch"] == "obscure-server 1.0"
    assert {c["match"] for c in cves} == {"keyword"}


def test_cpe_match_raises_confidence_and_dedupes_across_vendors(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_CACHE_PATH", str(tmp_path / "cache.json"))

    class Resp:
        def raise_for_status(self): pass
        def json(self): return NVD_PAYLOAD

    with patch("scanner.nvd.httpx.get", return_value=Resp()):
        cves = nvd.query_cves("nginx", "1.18.0")  # same payload from both vendors
    assert len(cves) == 3 and {c["match"] for c in cves} == {"cpe"}
    with patch("scanner.checks.tech_detection.nvd.query_cves", return_value=cves):
        f = next(x for x in check_tech_detection(FakeResponse({"Server": "nginx/1.18.0"}))
                 if x.metadata.get("cve") == "CVE-2021-0001")
    assert f.confidence == "medium" and "matched by CPE" in f.evidence
