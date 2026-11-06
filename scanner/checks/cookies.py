"""Cookie flags: Secure, HttpOnly, SameSite.

Vulnerability: a session cookie without HttpOnly can be read by JavaScript (XSS); without Secure
it travels over HTTP; without SameSite it's exposed to CSRF.
Example: an XSS runs document.cookie and sends the session to the attacker, who takes over the account.
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
        return [Finding(CHECK, Severity.INFO, "No cookie set by the response")]

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
                    CHECK, Severity.INFO, f"Cookie '{name}' has the right flags",
                    metadata={"cookie": name}, rule_id="cookies.ok"))
                continue
            sensitive = any(h in name.lower() for h in SESSION_HINTS)
            # A cookie that looks like a session one, missing Secure/HttpOnly, is the highest-impact case.
            critical_flag_missing = "Secure" in missing or "HttpOnly" in missing
            severity = Severity.MEDIUM if sensitive and critical_flag_missing else Severity.LOW
            findings.append(Finding(
                CHECK, severity, f"Cookie '{name}' missing flags: {', '.join(missing)}",
                f"The {name} cookie does not set: {', '.join(missing)}."
                + (" The name suggests a session/authentication cookie." if sensitive else ""),
                "Set Secure, HttpOnly and SameSite (Lax or Strict) on cookies.",
                {"cookie": name, "missing": missing},
                evidence=f"Set-Cookie: {name}=<value omitted>; missing {', '.join(missing)}",
                cwe="CWE-1004" if "HttpOnly" in missing else "CWE-614",
                references=[REFERENCE], confidence="high" if sensitive else "medium",
                rule_id="cookies.flags",
            ))
    return findings or [Finding(CHECK, Severity.INFO, "No cookie set by the response")]
