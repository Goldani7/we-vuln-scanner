from unittest.mock import patch

from scanner.checks.exposed_files import check_exposed_files
from scanner.finding import Severity


class Resp:
    def __init__(self, status=200, content=b"x"):
        self.status_code, self.content = status, content


def _run(handler):
    with patch("scanner.checks.exposed_files.requests.get", side_effect=lambda url, **kw: handler(url)):
        return check_exposed_files("https://ex.com")


def test_detects_exposed_env_and_admin():
    def handler(url):
        return Resp(200, b"SECRET=1") if url.endswith(("/.env", "/admin")) else Resp(404, b"")
    sev = {f.metadata["path"]: f.severity for f in _run(handler) if f.metadata}
    assert sev == {"/.env": Severity.HIGH, "/admin": Severity.LOW}


def test_soft_404_site_has_no_false_positives():
    findings = _run(lambda url: Resp(200, b"<html>app shell</html>"))
    assert len(findings) == 1 and findings[0].severity is Severity.INFO


def test_connection_errors_are_ignored():
    import requests
    def handler(url):
        raise requests.ConnectionError("boom")
    findings = _run(handler)
    assert findings[0].severity is Severity.INFO
