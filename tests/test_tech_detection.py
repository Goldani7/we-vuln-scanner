from unittest.mock import patch

import pytest

from scanner import nvd
from scanner.checks.tech_detection import check_tech_detection, severity_from_cvss
from scanner.finding import Severity


class FakeResponse:
    def __init__(self, headers):
        self.headers = headers


NVD_PAYLOAD = {"vulnerabilities": [
    {"cve": {"id": "CVE-2021-0001",
             "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Bug grave"}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}},
    {"cve": {"id": "CVE-2021-0002",
             "descriptions": [{"lang": "en", "value": "Bug médio"}],
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

    with patch("scanner.nvd.requests.get", return_value=Resp()) as get:
        first = nvd.query_cves("nginx", "1.18.0")
        second = nvd.query_cves("nginx", "1.18.0")
    assert first == second
    assert get.call_count == 1  # segunda chamada veio do cache
    assert get.call_args.kwargs["headers"] == {"apiKey": "secret"}
    assert get.call_args.kwargs["params"]["keywordSearch"] == "nginx 1.18.0"


def test_query_cves_network_error_raises_nvd_error(tmp_path, monkeypatch):
    import requests
    monkeypatch.setenv("NVD_CACHE_PATH", str(tmp_path / "cache.json"))
    with patch("scanner.nvd.requests.get", side_effect=requests.Timeout("t")):
        with pytest.raises(nvd.NVDError):
            nvd.query_cves("nginx", "1.18.0")
