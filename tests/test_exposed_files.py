import httpx

from scanner.checks.exposed_files import check_exposed_files
from scanner.finding import Severity

from .conftest import run_check

ENV = "APP_NAME=demo\nDB_PASSWORD=hunter2-super-secret\nAWS_SECRET_KEY=AKIAxxxx\n"


def site(files, default=(404, "not found")):
    def handler(request):
        status, body = files.get(request.url.path, default)
        return httpx.Response(status, content=body if isinstance(body, bytes) else body.encode())
    return handler


def by_rule(findings):
    return {f.rule: f for f in findings}


def test_env_is_critical_and_secrets_are_masked():
    findings = run_check(check_exposed_files, site({"/.env": (200, ENV)}))
    f = by_rule(findings)["exposed.env"]
    assert f.severity is Severity.CRITICAL and f.confidence == "high"
    assert "hunter2" not in f.evidence and "AKIAxxxx" not in f.evidence
    assert "DB_PASSWORD=****" in f.evidence


def test_soft_404_spa_has_no_false_positives():
    html = "<!doctype html><html><body>app</body></html>"
    findings = run_check(check_exposed_files, site({}, default=(200, html)))
    assert [f.severity for f in findings] == [Severity.INFO]


def test_html_page_at_env_path_is_rejected_even_if_it_looks_keyvalue():
    html = "<html><body>A=1\nB=2</body></html>"
    findings = run_check(check_exposed_files, site({"/.env": (200, html)}, default=(404, "")))
    assert "exposed.env" not in by_rule(findings)


def test_git_config_requires_signature():
    ok = run_check(check_exposed_files, site({"/.git/config": (200, "[core]\n\trepositoryformatversion = 0")}))
    assert by_rule(ok)["exposed.git"].severity is Severity.HIGH
    fake = run_check(check_exposed_files, site({"/.git/config": (200, "hello world")}))
    assert "exposed.git" not in by_rule(fake)


def test_private_key_evidence_never_includes_key_material():
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA-SECRET-MATERIAL\n"
    f = by_rule(run_check(check_exposed_files, site({"/id_rsa": (200, key)})))["exposed.private-key"]
    assert f.severity is Severity.CRITICAL and "SECRET-MATERIAL" not in f.evidence


def test_zip_backup_detected_by_magic_bytes():
    f = by_rule(run_check(check_exposed_files, site({"/backup.zip": (200, b"PK\x03\x04rest")})))
    assert f["exposed.backup"].severity is Severity.HIGH


def test_admin_found_only_when_differs_from_baseline():
    found = by_rule(run_check(check_exposed_files, site({"/admin": (200, "<html>login page here</html>")})))
    assert found["exposed.admin"].confidence == "low"
    # a server returning 403 for everything doesn't reveal a real /admin
    none = run_check(check_exposed_files, site({}, default=(403, "forbidden")))
    assert "exposed.admin" not in by_rule(none)


def test_robots_with_sensitive_disallow_is_low():
    robots = "User-agent: *\nDisallow: /admin-backup/\nDisallow: /img/"
    f = by_rule(run_check(check_exposed_files, site({"/robots.txt": (200, robots)})))["exposed.robots"]
    assert f.severity is Severity.LOW and "admin-backup" in f.evidence


def test_connection_errors_do_not_crash():
    def boom(request):
        raise httpx.ConnectError("refused")
    findings = run_check(check_exposed_files, boom)
    assert findings[0].severity is Severity.INFO
