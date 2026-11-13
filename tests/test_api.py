from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import app, limiter
from scanner.core import ALL_CHECKS
from scanner.finding import Finding, Severity

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_limiter():
    limiter.reset()


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_checks_lists_all_modules():
    r = client.get("/checks")
    assert r.status_code == 200
    assert [c["name"] for c in r.json()] == ALL_CHECKS
    assert all(c["description"] for c in r.json())


def test_scan_returns_findings():
    fake = [Finding("headers", Severity.HIGH, "CSP ausente")]
    with patch("api.main.scan", return_value=fake) as mock_scan:
        r = client.post("/scan", json={"url": "https://8.8.8.8", "checks": ["headers"]})
    assert r.status_code == 200
    assert r.json()[0]["severity"] == "high"
    args, kwargs = mock_scan.call_args
    assert args == ("https://8.8.8.8",) and kwargs["checks"] == ["headers"]
    cfg = kwargs["config"]  # untrusted callers: SSRF guard on, no active checks, bounded duration
    assert cfg.public_only and not cfg.allow_active and cfg.max_duration


@pytest.mark.parametrize("url", [
    "http://localhost", "http://127.0.0.1", "http://10.0.0.5",
    "http://192.168.1.1", "http://169.254.169.254/latest/meta-data",
    "ftp://8.8.8.8", "not-a-url",
])
def test_scan_rejects_ssrf_and_invalid_urls(url):
    with patch("api.main.scan") as mock_scan:
        r = client.post("/scan", json={"url": url})
    assert r.status_code == 422
    mock_scan.assert_not_called()


def test_scan_rejects_unknown_check():
    r = client.post("/scan", json={"url": "https://8.8.8.8", "checks": ["nope"]})
    assert r.status_code == 422


def test_scan_rate_limited():
    with patch("api.main.scan", return_value=[]):
        codes = [client.post("/scan", json={"url": "https://8.8.8.8"}).status_code
                 for _ in range(11)]
    assert codes[:10] == [200] * 10
    assert codes[10] == 429


def test_api_key_required_when_configured(monkeypatch):
    monkeypatch.setenv("WVS_API_KEY", "s3cret")
    with patch("api.main.scan", return_value=[]):
        assert client.post("/scan", json={"url": "https://8.8.8.8"}).status_code == 401
        bad = client.post("/scan", json={"url": "https://8.8.8.8"}, headers={"X-API-Key": "nope"})
        assert bad.status_code == 401
        ok = client.post("/scan", json={"url": "https://8.8.8.8"}, headers={"X-API-Key": "s3cret"})
        assert ok.status_code == 200
