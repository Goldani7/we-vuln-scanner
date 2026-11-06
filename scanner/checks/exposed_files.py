"""Exposed sensitive files, with false-positive mitigation.

Vulnerability: config files, backups and version-control directories published by mistake leak
secrets and source code.
Example: GET /.git/config confirms an exposed repository; tools like git-dumper download it
whole, including passwords in the history. /.env often holds database and API keys.
Ref.: OWASP A05:2021 (Security Misconfiguration); CWE-538, CWE-200.

False positives: a 200 status is NOT enough (SPAs and "friendly" error pages return 200 for
everything). Each probe validates the CONTENT against a signature of the expected file type
(e.g. `[core]` in .git/config, KEY=value lines in .env). Probes with no signature (/admin) are
compared against the response to a random path (soft-404 baseline). Secrets never enter the
evidence: values are masked.
Note: only a fixed list of paths is tested (no brute-force/wordlist).
"""
import asyncio
import re
import uuid
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urljoin

from ..finding import Finding, Severity
from ..http import RequestFailed

CHECK = "exposed_files"
OWASP_A05 = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
REMOVE = ("Remove the file from the web server or block access to it (e.g. `location ~ /\\. "
          "{{ deny all; }}` in nginx). {extra}")
ROTATE = "Treat the exposed secrets as compromised: revoke and rotate them."

_HTML = re.compile(r"<\s*(!doctype|html|head|body)\b", re.I)
_SECRET_KEY = re.compile(r"PASS|SECRET|KEY|TOKEN|CREDENTIAL|DSN|PRIVATE", re.I)


def _text(body: bytes) -> str:
    return body[:65536].decode("utf-8", "replace")


def _mask(line: str) -> str:
    return re.sub(r"([=:])\s*\S.*$", r"\1 ****", line.strip())[:120]


def _snippet(text: str, match, mask: bool = False) -> str:
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    line = text[start: end if end != -1 else None].strip()
    return _mask(line) if mask else line[:160]


def _regex(pattern: str, *, html_ok: bool = False, mask: bool = False, header_only: bool = False):
    rx = re.compile(pattern, re.I | re.M)

    def validate(body: bytes, ctype: str):
        text = _text(body)
        if not html_ok and _HTML.search(text[:2048]):
            return None  # an HTML page where a data file was expected = soft-404
        m = rx.search(text)
        if not m:
            return None
        return (m.group(0)[:60] if header_only else _snippet(text, m, mask)), None
    return validate


def _magic(prefix: bytes):
    def validate(body: bytes, ctype: str):
        if body.startswith(prefix) and "html" not in ctype.lower():
            return f"binary signature {prefix[:6]!r} at the start of the file", None
        return None
    return validate


def _env_validator(body: bytes, ctype: str):
    text = _text(body)
    if _HTML.search(text[:2048]):
        return None
    lines = re.findall(r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*\S.*$", text)
    secrets = [k for k in lines if _SECRET_KEY.search(k)]
    if len(lines) < 2 and not secrets:
        return None
    shown = "\n".join(f"{k}=****" for k in lines[:6])
    return shown + (f"\n… (+{len(lines) - 6} more variables)" if len(lines) > 6 else ""), None


def _robots_validator(body: bytes, ctype: str):
    text = _text(body)
    if not re.search(r"(?im)^\s*user-agent\s*:", text):
        return None
    disallows = re.findall(r"(?im)^\s*disallow\s*:\s*(\S+)", text)
    interesting = [d for d in disallows
                   if re.search(r"admin|backup|private|internal|secret|config|db|api|staging", d, re.I)]
    evidence = "\n".join(f"Disallow: {d}" for d in (interesting or disallows)[:10]) or "(no Disallow)"
    return evidence, (Severity.LOW if interesting else None)


@dataclass(frozen=True)
class Probe:
    path: str
    severity: Severity
    title: str
    validate: Optional[Callable]  # None => relies on the soft-404 baseline
    remediation: str
    cwe: str = "CWE-538"
    rule: str = ""
    statuses: tuple = (200,)


_FILE_FIX = REMOVE.format(extra="")
_SECRET_FIX = REMOVE.format(extra=ROTATE)

PROBES = [
    Probe("/.env", Severity.CRITICAL, "Exposed .env file with environment variables",
          _env_validator, _SECRET_FIX, "CWE-538", "exposed.env"),
    Probe("/.git/config", Severity.HIGH, "Exposed .git repository (config)",
          _regex(r"^\s*\[(core|remote\s+\"[^\"]+\"|branch\s+\"[^\"]+\")\]"),
          REMOVE.format(extra="Review the repository history for secrets and rotate them."),
          "CWE-540", "exposed.git"),
    Probe("/.git/HEAD", Severity.HIGH, "Exposed .git repository (HEAD)",
          _regex(r"^ref:\s*refs/"), REMOVE.format(extra=""), "CWE-540", "exposed.git"),
    Probe("/.DS_Store", Severity.MEDIUM, "Exposed .DS_Store file (lists file names)",
          _magic(b"\x00\x00\x00\x01Bud1"), _FILE_FIX, "CWE-538", "exposed.ds-store"),
    Probe("/.htpasswd", Severity.HIGH, "Exposed .htpasswd file (password hashes)",
          _regex(r"^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13}$)", mask=True),
          _SECRET_FIX, "CWE-522", "exposed.htpasswd"),
    Probe("/.aws/credentials", Severity.CRITICAL, "Exposed AWS credentials",
          _regex(r"aws_access_key_id\s*=", mask=True), _SECRET_FIX, "CWE-798", "exposed.aws"),
    Probe("/id_rsa", Severity.CRITICAL, "Exposed SSH private key",
          _regex(r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", header_only=True),
          _SECRET_FIX, "CWE-321", "exposed.private-key"),
    Probe("/.ssh/id_rsa", Severity.CRITICAL, "Exposed SSH private key",
          _regex(r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", header_only=True),
          _SECRET_FIX, "CWE-321", "exposed.private-key"),
    Probe("/wp-config.php.bak", Severity.CRITICAL, "Exposed wp-config.php backup",
          _regex(r"DB_PASSWORD|AUTH_KEY", html_ok=True, mask=True), _SECRET_FIX, "CWE-530", "exposed.wp-config"),
    Probe("/wp-config.php~", Severity.CRITICAL, "Exposed wp-config.php backup",
          _regex(r"DB_PASSWORD|AUTH_KEY", html_ok=True, mask=True), _SECRET_FIX, "CWE-530", "exposed.wp-config"),
    Probe("/backup.sql", Severity.CRITICAL, "Exposed database dump",
          _regex(r"CREATE TABLE|INSERT INTO|DROP TABLE"), _SECRET_FIX, "CWE-530", "exposed.sql-dump"),
    Probe("/dump.sql", Severity.CRITICAL, "Exposed database dump",
          _regex(r"CREATE TABLE|INSERT INTO|DROP TABLE"), _SECRET_FIX, "CWE-530", "exposed.sql-dump"),
    Probe("/database.sql", Severity.CRITICAL, "Exposed database dump",
          _regex(r"CREATE TABLE|INSERT INTO|DROP TABLE"), _SECRET_FIX, "CWE-530", "exposed.sql-dump"),
    Probe("/backup.zip", Severity.HIGH, "Exposed backup file (.zip)",
          _magic(b"PK\x03\x04"), _FILE_FIX, "CWE-530", "exposed.backup"),
    Probe("/backup.tar.gz", Severity.HIGH, "Exposed backup file (.tar.gz)",
          _magic(b"\x1f\x8b"), _FILE_FIX, "CWE-530", "exposed.backup"),
    Probe("/actuator/env", Severity.HIGH, "Exposed Spring Boot Actuator /env",
          _regex(r"propertySources|activeProfiles", html_ok=True),
          "Disable or protect the Actuator endpoints (management.endpoints.web.exposure.include) "
          "and rotate any exposed secrets.", "CWE-215", "exposed.actuator"),
    Probe("/phpinfo.php", Severity.MEDIUM, "Exposed phpinfo()",
          _regex(r"PHP Version|phpinfo\(\)", html_ok=True), _FILE_FIX, "CWE-200", "exposed.phpinfo"),
    Probe("/info.php", Severity.MEDIUM, "Exposed phpinfo()",
          _regex(r"PHP Version|phpinfo\(\)", html_ok=True), _FILE_FIX, "CWE-200", "exposed.phpinfo"),
    Probe("/server-status", Severity.MEDIUM, "Exposed Apache server-status",
          _regex(r"Apache Server Status", html_ok=True),
          "Restrict /server-status to localhost or disable mod_status.", "CWE-200", "exposed.server-status"),
    Probe("/phpmyadmin/", Severity.MEDIUM, "phpMyAdmin publicly accessible",
          _regex(r"phpMyAdmin", html_ok=True),
          "Restrict access by VPN/IP and require strong authentication; keep it updated.", "CWE-668", "exposed.phpmyadmin"),
    Probe("/adminer.php", Severity.MEDIUM, "Adminer publicly accessible",
          _regex(r"Adminer", html_ok=True),
          "Remove Adminer from production or restrict it by VPN/IP.", "CWE-668", "exposed.adminer"),
    Probe("/swagger.json", Severity.LOW, "Exposed API documentation (Swagger)",
          _regex(r"\"swagger\"|\"openapi\"", html_ok=True),
          "Restrict the documentation to authenticated users in production.", "CWE-200", "exposed.api-docs"),
    Probe("/openapi.json", Severity.LOW, "Exposed API documentation (OpenAPI)",
          _regex(r"\"openapi\"|\"swagger\"", html_ok=True),
          "Restrict the documentation to authenticated users in production.", "CWE-200", "exposed.api-docs"),
    Probe("/robots.txt", Severity.INFO, "robots.txt present", _robots_validator,
          "Don't use robots.txt to hide sensitive areas: it's public. Protect them with authentication.",
          "CWE-200", "exposed.robots"),
    Probe("/admin", Severity.LOW, "Admin panel found at /admin", None,
          "Restrict the panel by IP/VPN and require strong authentication (MFA).", "CWE-668",
          "exposed.admin", statuses=(200, 401)),
]


async def _fetch(ctx, url: str):
    try:
        return await ctx.client.request("GET", url, follow_redirects=False)
    except RequestFailed:
        return None


def _same_as_baseline(resp, baseline) -> bool:
    if baseline is None or resp.status_code != baseline.status_code:
        return False
    a, b = len(resp.content), len(baseline.content)
    return resp.content == baseline.content or abs(a - b) <= 0.1 * max(a, b, 1)


async def check_exposed_files(ctx) -> list:
    base_url = ctx.url
    baseline, *responses = await asyncio.gather(
        _fetch(ctx, urljoin(base_url, f"/{uuid.uuid4().hex}")),
        *[_fetch(ctx, urljoin(base_url, p.path)) for p in PROBES],
    )

    findings, seen_rules = [], set()
    for probe, resp in zip(PROBES, responses):
        if resp is None or resp.status_code not in probe.statuses:
            continue
        url = urljoin(base_url, probe.path)
        severity, confidence = probe.severity, "high"
        if probe.validate is not None:
            if not resp.content:
                continue
            result = probe.validate(resp.content, resp.headers.get("content-type", ""))
            if result is None:
                continue
            evidence, override = result
            severity = override or severity
        else:
            if _same_as_baseline(resp, baseline):
                continue  # soft-404: the server responds the same way to any path
            evidence, confidence = "(no content signature; verify manually)", "low"
            if resp.status_code == 401:
                severity, confidence = Severity.INFO, "medium"
                evidence = "HTTP 401: the resource exists and requires authentication"
        key = (probe.rule, probe.title)
        if key in seen_rules:
            continue
        seen_rules.add(key)
        findings.append(Finding(
            CHECK, severity, probe.title,
            f"GET {url} returned HTTP {resp.status_code} with {len(resp.content)} bytes "
            "and content matching the expected file type." if probe.validate else
            f"GET {url} returned HTTP {resp.status_code}, different from the response to a nonexistent path.",
            probe.remediation, {"path": probe.path, "url": url, "status": resp.status_code},
            evidence=evidence, cwe=probe.cwe, references=[OWASP_A05],
            confidence=confidence, rule_id=probe.rule,
        ))

    if not any(f.severity is not Severity.INFO for f in findings):
        findings.append(Finding(
            CHECK, Severity.INFO, "No common sensitive file exposed",
            f"{len(PROBES)} paths checked (content validated by signature).",
            rule_id="exposed.none",
        ))
    return findings
