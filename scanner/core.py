import asyncio
import dataclasses
import logging
from urllib.parse import urlparse

from .checks.cookies import check_cookies
from .checks.cors import check_cors
from .checks.email_dns import check_dkim, check_dmarc, check_dnsbl, check_spf
from .checks.exposed_files import check_exposed_files
from .checks.headers import check_headers
from .checks.misconfig import check_misconfig
from .checks.ssl_tls import check_ssl_tls
from .checks.subdomains import check_subdomains
from .checks.tech_detection import check_tech_detection
from .checks.waf import check_waf
from .finding import Finding, Severity
from .http import HttpClient, RequestFailed, ScanConfig, ScanContext
from .registry import CheckSpec, Registry

log = logging.getLogger(__name__)

REGISTRY = Registry()
for _spec in (
    CheckSpec("headers", "response", check_headers, "web",
              "Verifica headers de segurança (CSP, HSTS, X-Frame-Options...). Eles instruem o navegador a "
              "bloquear XSS, clickjacking e downgrade para HTTP."),
    CheckSpec("cookies", "response", check_cookies, "web",
              "Verifica as flags Secure, HttpOnly e SameSite dos cookies. Sem elas, cookies de sessão podem "
              "ser roubados via XSS, rede insegura ou CSRF."),
    CheckSpec("tech_detection", "response", check_tech_detection, "web",
              "Detecta software/versão expostos em Server/X-Powered-By e consulta CVEs na NVD, priorizadas "
              "por EPSS e CISA KEV."),  # consulta a NVD (requests): roda em thread
    CheckSpec("waf", "response", check_waf, "web",
              "Identifica passivamente WAF/CDN (Cloudflare, Akamai, CloudFront...) por headers, cookies e "
              "páginas de bloqueio. A borda mascara a origem e pode filtrar achados."),
    CheckSpec("ssl_tls", "url", check_ssl_tls, "web",
              "Verifica versões do TLS aceitas e validade do certificado. Protocolos antigos e certificados "
              "expirados permitem interceptação e quebram a confiança."),
    CheckSpec("cors", "async", check_cors, "web",
              "Testa se o CORS aceita origens arbitrárias. Uma política permissiva deixa sites maliciosos "
              "ler respostas autenticadas do usuário."),
    CheckSpec("exposed_files", "async", check_exposed_files, "web",
              "Procura arquivos sensíveis comuns (.env, .git, backups) e valida o conteúdo para evitar falsos "
              "positivos. Eles costumam vazar credenciais e código-fonte."),
    CheckSpec("misconfig", "async", check_misconfig, "web",
              "Verifica redirecionamento HTTP→HTTPS, método TRACE, listagem de diretório e páginas de erro "
              "com stack trace, que vazam informação sobre o servidor."),
    CheckSpec("subdomains", "async", check_subdomains, "recon",
              "Enumeração passiva de subdomínios via Certificate Transparency (crt.sh)."),
    CheckSpec("spf", "domain", check_spf, "email", "SPF: autoriza quais servidores enviam e-mail pelo domínio."),
    CheckSpec("dkim", "domain", check_dkim, "email", "DKIM: assinatura criptográfica dos e-mails enviados."),
    CheckSpec("dmarc", "domain", check_dmarc, "email", "DMARC: política contra e-mails falsificados."),
    CheckSpec("dnsbl", "domain", check_dnsbl, "email", "Reputação dos servidores de e-mail em listas DNSBL."),
):
    REGISTRY.register(_spec)
REGISTRY.load_plugins()  # checks de terceiros via entry point "wvs.checks"

ALL_CHECKS = REGISTRY.names("web")
EMAIL_CHECKS = REGISTRY.names("email")
RECON_CHECKS = REGISTRY.names("recon")
MODES = ("web", "email", "recon", "full")

# Visões por tipo de assinatura (derivadas do registro).
RESPONSE_CHECKS = REGISTRY.by_kind("response")  # sobre a resposta da página inicial (roda em thread)
ASYNC_CHECKS = REGISTRY.by_kind("async")        # recebem o ScanContext
URL_CHECKS = REGISTRY.by_kind("url")            # bloqueantes (socket): em thread
DOMAIN_CHECKS = REGISTRY.by_kind("domain")      # bloqueantes (DNS): em thread


def _failure(name: str, e: Exception) -> list:
    if isinstance(e, RequestFailed):
        return [Finding(name, Severity.INFO, f"Check '{name}' sem resposta do alvo", e.describe(),
                        "Verifique a disponibilidade e reduza --rate/--concurrency se houver bloqueio.",
                        rule_id=f"{name}.unreachable")]
    return [Finding(name, Severity.INFO, f"Check '{name}' falhou", f"{type(e).__name__}: {e}",
                    "Execute com -v para ver o traceback.", rule_id=f"{name}.error")]


async def _safe(name, awaitable) -> list:
    """Isola um check: nenhuma exceção (timeout, TLS, bug) derruba o scan inteiro."""
    log.debug("executando check %s", name)
    try:
        return await awaitable
    except Exception as e:  # noqa: BLE001
        log.debug("check %s falhou", name, exc_info=True)
        return _failure(name, e)


def _tag(findings: list, target: str) -> list:
    return [dataclasses.replace(f, target=f.target or target) for f in findings]


def _looks_blocked(s: dict) -> bool:
    """Muitos 403/406 em proporção alta sugerem bloqueio ativo (WAF/rate limit), não só arquivos protegidos."""
    return s["forbidden"] >= 10 and s["forbidden"] >= 0.5 * s["requests"]


def _rate_limit_notice(client: HttpClient) -> list:
    s = client.stats
    if not s["throttled"] and not s["failures"] and not _looks_blocked(s):
        return []
    return [Finding(
        "core", Severity.INFO, "Alvo limitou ou recusou requisições; resultados podem estar incompletos",
        f"{s['throttled']} resposta(s) 429, {s['forbidden']} resposta(s) 403/406, {s['failures']} falha(s) de rede, "
        f"{s['retries']} retentativa(s) em {s['requests']} requisição(ões).",
        "Reduza --rate e --concurrency, ou combine uma liberação do seu IP com o cliente.",
        dict(s), rule_id="core.throttled", confidence="high")]


def default_web_checks(config: ScanConfig) -> list:
    """Checks web padrão; os ativos só entram com allow_active."""
    return REGISTRY.names("web", include_active=config.allow_active)


async def scan_web_async(ctx: ScanContext, checks) -> list:
    checks = checks or default_web_checks(ctx.config)
    try:
        response = await ctx.index() if any(c in RESPONSE_CHECKS for c in checks) else None
    except RequestFailed as e:
        return [Finding("core", Severity.HIGH, f"Falha ao conectar ao alvo ({e.kind})", str(e),
                        "Verifique a URL, o certificado (use --insecure só para diagnóstico) e a disponibilidade.",
                        evidence=f"GET {ctx.url} → {e.describe()}", rule_id=f"core.connect-{e.kind}",
                        confidence="high")]
    jobs = []
    for name in checks:
        if name in RESPONSE_CHECKS:
            jobs.append(_safe(name, asyncio.to_thread(RESPONSE_CHECKS[name], response)))
        elif name in ASYNC_CHECKS:
            jobs.append(_safe(name, ASYNC_CHECKS[name](ctx)))
        elif name in URL_CHECKS:
            jobs.append(_safe(name, asyncio.to_thread(URL_CHECKS[name], ctx.url, timeout=ctx.config.timeout)))
    return [f for group in await asyncio.gather(*jobs) for f in group]


async def scan_email_async(domain: str, config: ScanConfig, checks=None) -> list:
    checks = checks or EMAIL_CHECKS
    jobs = [_safe(c, asyncio.to_thread(DOMAIN_CHECKS[c], domain, timeout=config.timeout)) for c in checks]
    return [f for group in await asyncio.gather(*jobs) for f in group]


def extract_domain(target: str) -> str:
    """Hostname de uma URL ou domínio puro ('https://a.com:8443/x' -> 'a.com')."""
    host = urlparse(target if "://" in target else f"//{target}").hostname
    return (host or "").rstrip(".").lower()


async def scan_target_async(target: str, mode: str = "full", web_checks=None,
                            config: ScanConfig = None, transport=None) -> list:
    if mode not in MODES:
        raise ValueError(f"modo inválido: {mode}")
    config = config or ScanConfig()
    url = target if "://" in target else f"https://{target}"
    findings = []
    async with HttpClient(config, transport=transport) as client:
        ctx = ScanContext(url, client, config)
        jobs = []
        if mode in ("web", "full"):
            jobs.append(scan_web_async(ctx, web_checks))
        if mode in ("recon", "full"):
            jobs.extend(_safe(name, ASYNC_CHECKS[name](ctx)) for name in RECON_CHECKS)
        if mode in ("email", "full"):
            jobs.append(scan_email_async(extract_domain(target), config))
        for group in await asyncio.gather(*jobs):
            findings.extend(group)
        findings.extend(_rate_limit_notice(client))
    return _tag(findings, url)


def scan_target(target: str, mode: str = "full", web_checks=None, timeout: float = 10,
                config: ScanConfig = None) -> list:
    """Ponto de entrada síncrono da CLI: aceita URL ou domínio."""
    config = config or ScanConfig(timeout=timeout)
    return asyncio.run(scan_target_async(target, mode, web_checks, config))


def scan(url: str, checks=None, timeout: int = 8, config: ScanConfig = None) -> list:
    """Scan web síncrono (usado pela API). Seguro de chamar de uma thread sem event loop."""
    return scan_target(url, mode="web", web_checks=checks, timeout=timeout, config=config)
