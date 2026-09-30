import requests

from .finding import Finding, Severity
from .checks.headers import check_headers
from .checks.cookies import check_cookies
from .checks.tech_detection import check_tech_detection
from .checks.ssl_tls import check_ssl_tls
from .checks.cors import check_cors
from .checks.exposed_files import check_exposed_files

ALL_CHECKS = ["headers", "cookies", "tech_detection", "ssl_tls", "cors", "exposed_files"]
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


def scan(url: str, checks=None, timeout: int = 8) -> list:
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
                findings.extend(RESPONSE_CHECKS[name](response))

    for name in checks:
        if name in URL_CHECKS:
            findings.extend(URL_CHECKS[name](url, timeout=timeout))
    return findings
