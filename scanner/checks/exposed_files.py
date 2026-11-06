"""Arquivos sensíveis expostos, com mitigação de falsos positivos.

Vulnerabilidade: arquivos de configuração, backups e diretórios de controle de versão publicados
por engano vazam segredos e código-fonte.
Exemplo: GET /.git/config confirma um repositório exposto; ferramentas como git-dumper o baixam
inteiro, incluindo senhas no histórico. /.env costuma conter chaves de banco e de API.
Ref.: OWASP A05:2021 (Security Misconfiguration); CWE-538, CWE-200.

Falsos positivos: um status 200 NÃO basta (SPAs e páginas de erro "amigáveis" respondem 200 a tudo).
Cada probe valida o CONTEÚDO contra uma assinatura do tipo de arquivo esperado (ex.: `[core]` em
.git/config, linhas CHAVE=valor em .env). Probes sem assinatura (/admin) são comparados com a
resposta a um caminho aleatório (baseline soft-404). Segredos nunca entram na evidência: os valores
são mascarados.
Nota: testa só uma lista fixa de caminhos (sem brute-force/wordlist).
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
REMOVE = ("Remova o arquivo do servidor web ou bloqueie o acesso (ex.: `location ~ /\\. {{ deny all; }}` "
          "no nginx). {extra}")
ROTATE = "Considere os segredos comprometidos: revogue e rotacione-os."

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
            return None  # página HTML onde se esperava um arquivo de dados = soft-404
        m = rx.search(text)
        if not m:
            return None
        return (m.group(0)[:60] if header_only else _snippet(text, m, mask)), None
    return validate


def _magic(prefix: bytes):
    def validate(body: bytes, ctype: str):
        if body.startswith(prefix) and "html" not in ctype.lower():
            return f"assinatura binária {prefix[:6]!r} no início do arquivo", None
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
    return shown + (f"\n… (+{len(lines) - 6} variáveis)" if len(lines) > 6 else ""), None


def _robots_validator(body: bytes, ctype: str):
    text = _text(body)
    if not re.search(r"(?im)^\s*user-agent\s*:", text):
        return None
    disallows = re.findall(r"(?im)^\s*disallow\s*:\s*(\S+)", text)
    interesting = [d for d in disallows
                   if re.search(r"admin|backup|private|internal|secret|config|db|api|staging", d, re.I)]
    evidence = "\n".join(f"Disallow: {d}" for d in (interesting or disallows)[:10]) or "(sem Disallow)"
    return evidence, (Severity.LOW if interesting else None)


@dataclass(frozen=True)
class Probe:
    path: str
    severity: Severity
    title: str
    validate: Optional[Callable]  # None => depende do baseline soft-404
    remediation: str
    cwe: str = "CWE-538"
    rule: str = ""
    statuses: tuple = (200,)


_FILE_FIX = REMOVE.format(extra="")
_SECRET_FIX = REMOVE.format(extra=ROTATE)

PROBES = [
    Probe("/.env", Severity.CRITICAL, "Arquivo .env exposto com variáveis de ambiente",
          _env_validator, _SECRET_FIX, "CWE-538", "exposed.env"),
    Probe("/.git/config", Severity.HIGH, "Repositório .git exposto (config)",
          _regex(r"^\s*\[(core|remote\s+\"[^\"]+\"|branch\s+\"[^\"]+\")\]"),
          REMOVE.format(extra="Revise o histórico do repositório por segredos e rotacione-os."),
          "CWE-540", "exposed.git"),
    Probe("/.git/HEAD", Severity.HIGH, "Repositório .git exposto (HEAD)",
          _regex(r"^ref:\s*refs/"), REMOVE.format(extra=""), "CWE-540", "exposed.git"),
    Probe("/.DS_Store", Severity.MEDIUM, "Arquivo .DS_Store exposto (lista nomes de arquivos)",
          _magic(b"\x00\x00\x00\x01Bud1"), _FILE_FIX, "CWE-538", "exposed.ds-store"),
    Probe("/.htpasswd", Severity.HIGH, "Arquivo .htpasswd exposto (hashes de senha)",
          _regex(r"^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13}$)", mask=True),
          _SECRET_FIX, "CWE-522", "exposed.htpasswd"),
    Probe("/.aws/credentials", Severity.CRITICAL, "Credenciais AWS expostas",
          _regex(r"aws_access_key_id\s*=", mask=True), _SECRET_FIX, "CWE-798", "exposed.aws"),
    Probe("/id_rsa", Severity.CRITICAL, "Chave SSH privada exposta",
          _regex(r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", header_only=True),
          _SECRET_FIX, "CWE-321", "exposed.private-key"),
    Probe("/.ssh/id_rsa", Severity.CRITICAL, "Chave SSH privada exposta",
          _regex(r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", header_only=True),
          _SECRET_FIX, "CWE-321", "exposed.private-key"),
    Probe("/wp-config.php.bak", Severity.CRITICAL, "Backup do wp-config.php exposto",
          _regex(r"DB_PASSWORD|AUTH_KEY", html_ok=True, mask=True), _SECRET_FIX, "CWE-530", "exposed.wp-config"),
    Probe("/wp-config.php~", Severity.CRITICAL, "Backup do wp-config.php exposto",
          _regex(r"DB_PASSWORD|AUTH_KEY", html_ok=True, mask=True), _SECRET_FIX, "CWE-530", "exposed.wp-config"),
    Probe("/backup.sql", Severity.CRITICAL, "Dump de banco de dados exposto",
          _regex(r"CREATE TABLE|INSERT INTO|DROP TABLE"), _SECRET_FIX, "CWE-530", "exposed.sql-dump"),
    Probe("/dump.sql", Severity.CRITICAL, "Dump de banco de dados exposto",
          _regex(r"CREATE TABLE|INSERT INTO|DROP TABLE"), _SECRET_FIX, "CWE-530", "exposed.sql-dump"),
    Probe("/database.sql", Severity.CRITICAL, "Dump de banco de dados exposto",
          _regex(r"CREATE TABLE|INSERT INTO|DROP TABLE"), _SECRET_FIX, "CWE-530", "exposed.sql-dump"),
    Probe("/backup.zip", Severity.HIGH, "Arquivo de backup (.zip) exposto",
          _magic(b"PK\x03\x04"), _FILE_FIX, "CWE-530", "exposed.backup"),
    Probe("/backup.tar.gz", Severity.HIGH, "Arquivo de backup (.tar.gz) exposto",
          _magic(b"\x1f\x8b"), _FILE_FIX, "CWE-530", "exposed.backup"),
    Probe("/actuator/env", Severity.HIGH, "Spring Boot Actuator /env exposto",
          _regex(r"propertySources|activeProfiles", html_ok=True),
          "Desabilite ou proteja os endpoints do Actuator (management.endpoints.web.exposure.include) "
          "e rotacione segredos expostos.", "CWE-215", "exposed.actuator"),
    Probe("/phpinfo.php", Severity.MEDIUM, "phpinfo() exposto",
          _regex(r"PHP Version|phpinfo\(\)", html_ok=True), _FILE_FIX, "CWE-200", "exposed.phpinfo"),
    Probe("/info.php", Severity.MEDIUM, "phpinfo() exposto",
          _regex(r"PHP Version|phpinfo\(\)", html_ok=True), _FILE_FIX, "CWE-200", "exposed.phpinfo"),
    Probe("/server-status", Severity.MEDIUM, "Apache server-status exposto",
          _regex(r"Apache Server Status", html_ok=True),
          "Restrinja /server-status a localhost ou desabilite o mod_status.", "CWE-200", "exposed.server-status"),
    Probe("/phpmyadmin/", Severity.MEDIUM, "phpMyAdmin acessível publicamente",
          _regex(r"phpMyAdmin", html_ok=True),
          "Restrinja o acesso por VPN/IP e exija autenticação forte; mantenha atualizado.", "CWE-668", "exposed.phpmyadmin"),
    Probe("/adminer.php", Severity.MEDIUM, "Adminer acessível publicamente",
          _regex(r"Adminer", html_ok=True),
          "Remova o Adminer de produção ou restrinja por VPN/IP.", "CWE-668", "exposed.adminer"),
    Probe("/swagger.json", Severity.LOW, "Documentação de API (Swagger) exposta",
          _regex(r"\"swagger\"|\"openapi\"", html_ok=True),
          "Restrinja a documentação a usuários autenticados em produção.", "CWE-200", "exposed.api-docs"),
    Probe("/openapi.json", Severity.LOW, "Documentação de API (OpenAPI) exposta",
          _regex(r"\"openapi\"|\"swagger\"", html_ok=True),
          "Restrinja a documentação a usuários autenticados em produção.", "CWE-200", "exposed.api-docs"),
    Probe("/robots.txt", Severity.INFO, "robots.txt presente", _robots_validator,
          "Não use robots.txt para esconder áreas sensíveis: ele é público. Proteja-as com autenticação.",
          "CWE-200", "exposed.robots"),
    Probe("/admin", Severity.LOW, "Painel administrativo encontrado em /admin", None,
          "Restrinja o painel por IP/VPN e exija autenticação forte (MFA).", "CWE-668",
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
                continue  # soft-404: o servidor responde igual a qualquer caminho
            evidence, confidence = "(sem assinatura de conteúdo; confirme manualmente)", "low"
            if resp.status_code == 401:
                severity, confidence = Severity.INFO, "medium"
                evidence = "HTTP 401: o recurso existe e exige autenticação"
        key = (probe.rule, probe.title)
        if key in seen_rules:
            continue
        seen_rules.add(key)
        findings.append(Finding(
            CHECK, severity, probe.title,
            f"GET {url} retornou HTTP {resp.status_code} com {len(resp.content)} bytes "
            "e conteúdo compatível com o tipo de arquivo esperado." if probe.validate else
            f"GET {url} retornou HTTP {resp.status_code}, diferente da resposta a um caminho inexistente.",
            probe.remediation, {"path": probe.path, "url": url, "status": resp.status_code},
            evidence=evidence, cwe=probe.cwe, references=[OWASP_A05],
            confidence=confidence, rule_id=probe.rule,
        ))

    if not any(f.severity is not Severity.INFO for f in findings):
        findings.append(Finding(
            CHECK, Severity.INFO, "Nenhum arquivo sensível comum exposto",
            f"{len(PROBES)} caminhos verificados (conteúdo validado por assinatura).",
            rule_id="exposed.none",
        ))
    return findings
