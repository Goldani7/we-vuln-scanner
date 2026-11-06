import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests

from .finding import Finding, Severity
from .checks.headers import check_headers
from .checks.cookies import check_cookies
from .checks.tech_detection import check_tech_detection
from .checks.ssl_tls import check_ssl_tls
from .checks.cors import check_cors
from .checks.exposed_files import check_exposed_files
from .checks.email_dns import check_spf, check_dkim, check_dmarc, check_dnsbl

log = logging.getLogger(__name__)

ALL_CHECKS = ["headers", "cookies", "tech_detection", "ssl_tls", "cors", "exposed_files"]
EMAIL_CHECKS = ["spf", "dkim", "dmarc", "dnsbl"]
MODES = ("web", "email", "full")
RESPONSE_CHECKS = {
    "headers": check_headers,
    "cookies": check_cookies,
    "tech_detection": check_tech_detection,
}
URL_CHECKS = {
    "ssl_tls": check_ssl_tls,
    "cors": check_cors,
    "exposed_files": check_exposed_files,
}
DOMAIN_CHECKS = {
    "spf": check_spf,
    "dkim": check_dkim,
    "dmarc": check_dmarc,
    "dnsbl": check_dnsbl,
}


def _safe(name, fn, *args, **kwargs) -> list:
    """Executa um check sem deixar uma exceção inesperada derrubar o scan inteiro."""
    log.debug("executando check %s", name)
    try:
        return fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001 - isolamos qualquer falha de um check
        log.debug("check %s falhou", name, exc_info=True)
        return [Finding(
            name, Severity.INFO, f"Check '{name}' falhou",
            f"{type(e).__name__}: {e}", "Execute com -v para ver o traceback.",
        )]


def scan(url: str, checks=None, timeout: int = 8) -> list:
    """Scan web. Os checks independentes de resposta rodam em paralelo."""
    checks = checks or ALL_CHECKS
    findings = []

    if any(c in RESPONSE_CHECKS for c in checks):
        try:
            response = requests.get(url, timeout=timeout)
        except requests.RequestException as e:
            return [Finding(
                "core", Severity.HIGH, "Falha ao conectar ao alvo", str(e),
                "Verifique a URL e a disponibilidade do alvo.",
            )]
        for name in checks:
            if name in RESPONSE_CHECKS:
                findings.extend(_safe(name, RESPONSE_CHECKS[name], response))

    url_checks = [c for c in checks if c in URL_CHECKS]
    if url_checks:
        with ThreadPoolExecutor(max_workers=len(url_checks)) as pool:
            futures = [pool.submit(_safe, c, URL_CHECKS[c], url, timeout=timeout) for c in url_checks]
            for fut in futures:
                findings.extend(fut.result())
    return findings


def scan_email(domain: str, checks=None, timeout: int = 8) -> list:
    """Scan de e-mail/DNS (SPF, DKIM, DMARC, DNSBL), com os checks em paralelo."""
    checks = checks or EMAIL_CHECKS
    with ThreadPoolExecutor(max_workers=len(checks)) as pool:
        futures = [pool.submit(_safe, c, DOMAIN_CHECKS[c], domain, timeout=timeout) for c in checks]
        return [f for fut in futures for f in fut.result()]


def extract_domain(target: str) -> str:
    """Hostname de uma URL ou domínio puro ('https://a.com:8443/x' -> 'a.com')."""
    host = urlparse(target if "://" in target else f"//{target}").hostname
    return (host or "").rstrip(".").lower()


def scan_target(target: str, mode: str = "full", web_checks=None, timeout: int = 8) -> list:
    """Ponto de entrada da CLI: aceita URL ou domínio e roda os módulos do modo escolhido."""
    if mode not in MODES:
        raise ValueError(f"modo inválido: {mode}")
    findings = []
    if mode in ("web", "full"):
        url = target if "://" in target else f"https://{target}"
        findings.extend(scan(url, checks=web_checks, timeout=timeout))
    if mode in ("email", "full"):
        findings.extend(scan_email(extract_domain(target), timeout=timeout))
    return findings
