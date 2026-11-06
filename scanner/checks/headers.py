"""Headers de segurança HTTP, avaliando o VALOR e não só a presença.

Vulnerabilidade: sem CSP/X-Frame-Options/HSTS o navegador não tem instruções para bloquear
XSS, clickjacking ou downgrade para HTTP. Um header presente mas fraco (CSP com 'unsafe-inline',
HSTS com max-age curto) dá falsa sensação de segurança.
Exemplo: sem X-Frame-Options/frame-ancestors, o atacante embute o site num <iframe> invisível e
engana o usuário a clicar em botões (clickjacking).
Ref.: OWASP Secure Headers Project; OWASP A05:2021 (Security Misconfiguration); CWE-693.
"""
import re

from ..finding import Finding, Severity

CHECK = "headers"
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
HSTS_MIN_AGE = 15552000  # 180 dias


def _f(rule, severity, title, detail, remediation, header, evidence="", cwe="CWE-693", confidence="high"):
    return Finding(
        CHECK, severity, title, detail, remediation, {"header": header}, evidence=evidence,
        cwe=cwe, references=[OWASP_HEADERS], confidence=confidence, rule_id=f"headers.{rule}",
    )


def _directives(csp: str) -> dict:
    out = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


def _csp(headers) -> list:
    name = "Content-Security-Policy"
    value = headers.get(name)
    if not value:
        report_only = headers.get("Content-Security-Policy-Report-Only")
        detail = "A resposta não contém Content-Security-Policy."
        if report_only:
            detail += " Existe apenas Content-Security-Policy-Report-Only, que não bloqueia nada."
        return [_f("csp-missing", Severity.MEDIUM, f"Header {name} ausente", detail,
                   "Defina uma CSP restritiva (ex.: default-src 'self'; object-src 'none'; "
                   "base-uri 'self'; frame-ancestors 'self'). Comece em Report-Only para testar.",
                   name, evidence="ausente", cwe="CWE-1021")]
    d = _directives(value)
    script = d.get("script-src", d.get("default-src", []))
    issues = []
    if "'unsafe-inline'" in script and not any(t.startswith(("'nonce-", "'sha")) for t in script):
        issues.append((Severity.MEDIUM, "unsafe-inline",
                       "script-src permite 'unsafe-inline', anulando a proteção contra XSS."))
    if "'unsafe-eval'" in script:
        issues.append((Severity.LOW, "unsafe-eval", "script-src permite 'unsafe-eval'."))
    if any(t in ("*", "data:", "http:", "https:") for t in script):
        issues.append((Severity.MEDIUM, "wildcard-source",
                       "script-src aceita fontes amplas (*, data:, http: ou https:), permitindo "
                       "carregar scripts de qualquer origem."))
    if "default-src" not in d:
        if "object-src" not in d:
            issues.append((Severity.LOW, "no-object-src", "Sem object-src nem default-src: plugins liberados."))
        if "base-uri" not in d:
            issues.append((Severity.LOW, "no-base-uri", "Sem base-uri: injeção de <base> pode redirecionar URLs relativas."))
    if not issues:
        return [_f("csp-ok", Severity.INFO, f"Header {name} presente", value[:300], "", name, evidence=value[:300])]
    return [
        _f(f"csp-{rule}", sev, f"CSP fraca: {rule}", msg,
           "Remova diretivas inseguras; use nonces/hashes em vez de 'unsafe-inline' e liste "
           "origens explícitas.", name, evidence=f"{name}: {value[:300]}")
        for sev, rule, msg in issues
    ]


def _hsts(headers, is_https: bool) -> list:
    name = "Strict-Transport-Security"
    value = headers.get(name)
    if not is_https:
        return []  # HSTS só vale sobre HTTPS; em HTTP o navegador ignora o header
    if not value:
        return [_f("hsts-missing", Severity.MEDIUM, f"Header {name} ausente",
                   "Sem HSTS o navegador aceita a primeira requisição em HTTP, permitindo "
                   "downgrade e interceptação (sslstrip).",
                   "Adicione 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                   name, evidence="ausente", cwe="CWE-319")]
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    if not m:
        return [_f("hsts-invalid", Severity.LOW, "HSTS sem max-age válido", f"{name}: {value}",
                   "Defina max-age (ex.: 31536000).", name, evidence=f"{name}: {value}", cwe="CWE-319")]
    age = int(m.group(1))
    out = []
    if age < HSTS_MIN_AGE:
        out.append(_f("hsts-short", Severity.LOW, f"HSTS com max-age curto ({age}s)",
                      f"max-age de {age}s (< 180 dias) reduz a janela de proteção.",
                      "Use max-age de pelo menos 31536000 (1 ano).", name,
                      evidence=f"{name}: {value}", cwe="CWE-319"))
    if "includesubdomains" not in value.lower():
        out.append(_f("hsts-no-subdomains", Severity.LOW, "HSTS sem includeSubDomains",
                      "Subdomínios continuam acessíveis em HTTP e podem ser usados para roubar cookies.",
                      "Adicione includeSubDomains (após verificar que todos os subdomínios suportam HTTPS).",
                      name, evidence=f"{name}: {value}", cwe="CWE-319"))
    return out or [_f("hsts-ok", Severity.INFO, f"Header {name} presente", value, "", name, evidence=value)]


def _xfo(headers, csp_value) -> list:
    name = "X-Frame-Options"
    value = headers.get(name)
    has_frame_ancestors = bool(csp_value and "frame-ancestors" in csp_value.lower())
    if not value:
        if has_frame_ancestors:
            return [_f("xfo-covered", Severity.INFO, f"Header {name} ausente (coberto por frame-ancestors)",
                       "A CSP define frame-ancestors, que substitui o X-Frame-Options.", "", name)]
        return [_f("xfo-missing", Severity.MEDIUM, f"Header {name} ausente",
                   "Nenhuma proteção contra clickjacking: a página pode ser embutida em iframes de "
                   "qualquer site.",
                   "Use 'X-Frame-Options: DENY' ou SAMEORIGIN, ou CSP frame-ancestors.",
                   name, evidence="ausente (e sem frame-ancestors na CSP)", cwe="CWE-1021")]
    v = value.strip().upper()
    if v in ("DENY", "SAMEORIGIN"):
        return [_f("xfo-ok", Severity.INFO, f"Header {name} presente", value, "", name, evidence=value)]
    return [_f("xfo-invalid", Severity.LOW, f"{name} com valor inválido ou obsoleto",
               f"Valor '{value}': ALLOW-FROM não é suportado por navegadores modernos.",
               "Use DENY/SAMEORIGIN ou CSP frame-ancestors.", name,
               evidence=f"{name}: {value}", cwe="CWE-1021")]


def _simple(headers, name, rule, ok, missing_sev, missing_msg, remediation, bad_msg=None) -> list:
    value = headers.get(name)
    if not value:
        return [_f(f"{rule}-missing", missing_sev, f"Header {name} ausente", missing_msg,
                   remediation, name, evidence="ausente")]
    if ok(value):
        return [_f(f"{rule}-ok", Severity.INFO, f"Header {name} presente", value, "", name, evidence=value)]
    return [_f(f"{rule}-weak", Severity.LOW, f"{name} com valor fraco", bad_msg or f"Valor: {value}",
               remediation, name, evidence=f"{name}: {value}")]


def _info_disclosure(headers) -> list:
    out = []
    for name in ("X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        value = headers.get(name)
        if value:
            out.append(_f(f"leak-{name.lower()}", Severity.LOW, f"Header {name} expõe tecnologia",
                          f"{name}: {value}", f"Remova o header {name} da resposta.", name,
                          evidence=f"{name}: {value}", cwe="CWE-200"))
    return out


def check_headers(response) -> list:
    h = response.headers
    url = getattr(response, "url", None)
    is_https = getattr(url, "scheme", "https") == "https"
    findings = []
    findings += _csp(h)
    findings += _hsts(h, is_https)
    findings += _xfo(h, h.get("Content-Security-Policy"))
    findings += _simple(
        h, "X-Content-Type-Options", "xcto", lambda v: v.strip().lower() == "nosniff", Severity.LOW,
        "Sem nosniff o navegador pode interpretar arquivos com MIME errado como script.",
        "Adicione 'X-Content-Type-Options: nosniff'.", "Valor deve ser exatamente 'nosniff'.")
    findings += _simple(
        h, "Referrer-Policy", "referrer",
        lambda v: v.strip().lower() not in ("unsafe-url", "no-referrer-when-downgrade", ""),
        Severity.LOW, "URLs completas (com tokens/IDs) podem vazar no header Referer para terceiros.",
        "Defina 'Referrer-Policy: strict-origin-when-cross-origin'.",
        "Esta política envia a URL completa a terceiros.")
    for name, why in (
        ("Permissions-Policy", "restringe APIs do navegador (câmera, geolocalização...)"),
        ("Cross-Origin-Opener-Policy", "isola a janela contra ataques cross-origin (XS-Leaks)"),
        ("Cross-Origin-Resource-Policy", "impede que outros sites carreguem seus recursos"),
    ):
        if h.get(name):
            findings.append(_f(name.lower(), Severity.INFO, f"Header {name} presente", h[name], "", name, evidence=h[name]))
        else:
            findings.append(_f(f"{name.lower()}-missing", Severity.INFO, f"Header {name} ausente",
                               f"Opcional, mas {why}.", f"Considere definir {name}.", name, evidence="ausente"))
    findings += _info_disclosure(h)
    return findings
