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
}


def check_exposed_files(url: str, timeout: int = 8) -> list:
    findings = []
    for path, severity in SENSITIVE_PATHS.items():
        target = urljoin(url, path)
        try:
            r = requests.get(target, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code == 200 and r.content:
            findings.append(Finding(
                CHECK, severity, f"Arquivo sensível acessível: {path}",
                f"GET {target} retornou 200 com {len(r.content)} bytes.",
                "Remova o arquivo do servidor web ou bloqueie o acesso.",
                {"path": path, "url": target},
            ))
    if not findings:
        findings.append(Finding(
            CHECK, Severity.INFO, "Nenhum arquivo sensível comum exposto",
            f"{len(SENSITIVE_PATHS)} caminhos verificados.",
        ))
    return findings
