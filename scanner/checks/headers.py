"""Headers de segurança HTTP.

Vulnerabilidade: sem CSP/X-Frame-Options/HSTS o navegador não tem instruções para bloquear
XSS, clickjacking ou downgrade para HTTP.
Exemplo: sem X-Frame-Options, o atacante embute o site num <iframe> invisível e engana o
usuário a clicar em botões (clickjacking).
Ref.: OWASP Secure Headers Project; OWASP A05:2021 (Security Misconfiguration); CWE-693.
"""
from ..finding import Finding, Severity

CHECK = "headers"

# header -> (severidade se ausente, recomendação)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        Severity.HIGH,
        "Defina uma CSP restritiva para mitigar XSS e injeção de conteúdo.",
    ),
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "Adicione HSTS (ex.: max-age=31536000; includeSubDomains).",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "Use X-Frame-Options: DENY ou SAMEORIGIN (ou frame-ancestors na CSP).",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Adicione X-Content-Type-Options: nosniff.",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Defina Referrer-Policy (ex.: strict-origin-when-cross-origin).",
    ),
    "Permissions-Policy": (
        Severity.INFO,
        "Considere restringir APIs do navegador com Permissions-Policy.",
    ),
}


def check_headers(response) -> list:
    findings = []
    for name, (severity, recommendation) in SECURITY_HEADERS.items():
        value = response.headers.get(name)
        if value:
            findings.append(Finding(
                check=CHECK,
                severity=Severity.INFO,
                title=f"Header {name} presente",
                detail=f"{name}: {value}",
                metadata={"header": name},
            ))
        else:
            findings.append(Finding(
                check=CHECK,
                severity=severity,
                title=f"Header {name} ausente",
                detail=f"A resposta não contém o header {name}.",
                recommendation=recommendation,
                metadata={"header": name},
            ))
    return findings
