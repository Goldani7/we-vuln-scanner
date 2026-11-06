"""Arquivos sensíveis expostos.

Vulnerabilidade: arquivos de configuração, backups e diretórios de controle de versão publicados
por engano vazam segredos e código-fonte.
Exemplo: GET /.git/config confirma um repositório exposto; ferramentas como git-dumper o baixam
inteiro, incluindo senhas no histórico. /.env costuma conter chaves de banco e de API.
Ref.: OWASP A05:2021 (Security Misconfiguration); CWE-538.
Nota: testa só uma lista fixa e pequena de caminhos (sem brute-force).
"""
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

import requests

from ..finding import Finding, Severity

CHECK = "exposed_files"

SENSITIVE_PATHS = {
    "/.env": Severity.HIGH,
    "/.git/config": Severity.HIGH,
    "/.git/HEAD": Severity.HIGH,
    "/wp-config.php.bak": Severity.HIGH,
    "/backup.zip": Severity.HIGH,
    "/.DS_Store": Severity.MEDIUM,
    "/server-status": Severity.MEDIUM,
    "/phpinfo.php": Severity.MEDIUM,
    "/admin": Severity.LOW,
    "/robots.txt": Severity.INFO,
}
MAX_WORKERS = 8


def _fetch(url: str, timeout: int):
    try:
        return requests.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None


def check_exposed_files(url: str, timeout: int = 8) -> list:
    # Soft-404: sites que respondem 200 para qualquer caminho gerariam falsos positivos.
    # Se um caminho aleatório responde 200, só aceitamos achados com conteúdo diferente dele.
    probe = _fetch(urljoin(url, f"/{uuid.uuid4().hex}"), timeout)
    soft_404 = probe.content if probe is not None and probe.status_code == 200 else None

    targets = {path: urljoin(url, path) for path in SENSITIVE_PATHS}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        responses = dict(zip(targets, pool.map(lambda t: _fetch(t, timeout), targets.values())))

    findings = []
    for path, r in responses.items():
        if r is None or r.status_code != 200 or not r.content:
            continue
        if soft_404 is not None and r.content == soft_404:
            continue
        severity = SENSITIVE_PATHS[path]
        recommendation = "Remova o arquivo do servidor web ou bloqueie o acesso."
        if path == "/robots.txt":
            recommendation = "Confirme que o robots.txt não lista caminhos internos que você quer esconder."
        elif path == "/admin":
            recommendation = "Restrinja o painel por IP/VPN e exija autenticação forte (MFA)."
        findings.append(Finding(
            CHECK, severity, f"Arquivo sensível acessível: {path}",
            f"GET {targets[path]} retornou 200 com {len(r.content)} bytes.",
            recommendation, {"path": path, "url": targets[path]},
        ))
    if not any(f.severity is not Severity.INFO for f in findings):
        findings.append(Finding(
            CHECK, Severity.INFO, "Nenhum arquivo sensível comum exposto",
            f"{len(SENSITIVE_PATHS)} caminhos verificados.",
        ))
    return findings
