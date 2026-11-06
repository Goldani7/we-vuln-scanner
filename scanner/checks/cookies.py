"""Flags de cookies: Secure, HttpOnly, SameSite.

Vulnerabilidade: cookie de sessão sem HttpOnly é lido por JavaScript (XSS); sem Secure trafega
em HTTP; sem SameSite fica exposto a CSRF.
Exemplo: um XSS executa document.cookie e envia a sessão ao atacante, que assume a conta.
Ref.: OWASP Session Management Cheat Sheet; CWE-614, CWE-1004, CWE-352.
"""
from http.cookies import CookieError, SimpleCookie

from ..finding import Finding, Severity

CHECK = "cookies"
SESSION_HINTS = ("sess", "sid", "auth", "token", "jwt", "login", "csrf")
REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"


def _set_cookie_headers(response) -> list:
    getter = getattr(response.headers, "get_list", None)  # httpx
    return getter("set-cookie") if getter else [
        v for k, v in response.headers.items() if k.lower() == "set-cookie"]


def check_cookies(response) -> list:
    raw_headers = _set_cookie_headers(response)
    if not raw_headers:
        return [Finding(CHECK, Severity.INFO, "Nenhum cookie definido pela resposta")]

    findings = []
    for raw in raw_headers:
        try:
            jar = SimpleCookie()
            jar.load(raw)
        except CookieError:
            continue
        for name, morsel in jar.items():
            missing = [flag for flag, present in (
                ("Secure", bool(morsel["secure"])),
                ("HttpOnly", bool(morsel["httponly"])),
                ("SameSite", bool(morsel["samesite"])),
            ) if not present]
            if not missing:
                findings.append(Finding(
                    CHECK, Severity.INFO, f"Cookie '{name}' com flags adequadas",
                    metadata={"cookie": name}, rule_id="cookies.ok"))
                continue
            sensitive = any(h in name.lower() for h in SESSION_HINTS)
            # Cookie que parece de sessão sem Secure/HttpOnly é o caso de maior impacto.
            critical_flag_missing = "Secure" in missing or "HttpOnly" in missing
            severity = Severity.MEDIUM if sensitive and critical_flag_missing else Severity.LOW
            findings.append(Finding(
                CHECK, severity, f"Cookie '{name}' sem flags: {', '.join(missing)}",
                f"O cookie {name} não define: {', '.join(missing)}."
                + (" O nome sugere um cookie de sessão/autenticação." if sensitive else ""),
                "Defina Secure, HttpOnly e SameSite (Lax ou Strict) nos cookies.",
                {"cookie": name, "missing": missing},
                evidence=f"Set-Cookie: {name}=<valor omitido>; faltando {', '.join(missing)}",
                cwe="CWE-1004" if "HttpOnly" in missing else "CWE-614",
                references=[REFERENCE], confidence="high" if sensitive else "medium",
                rule_id="cookies.flags",
            ))
    return findings or [Finding(CHECK, Severity.INFO, "Nenhum cookie definido pela resposta")]
