from ..finding import Finding, Severity

CHECK = "cookies"


def check_cookies(response) -> list:
    cookies = list(response.cookies)
    if not cookies:
        return [Finding(CHECK, Severity.INFO, "Nenhum cookie definido pela resposta")]

    findings = []
    for c in cookies:
        missing = []
        if not c.secure:
            missing.append("Secure")
        if not (c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly")):
            missing.append("HttpOnly")
        if not (c.has_nonstandard_attr("SameSite") or c.has_nonstandard_attr("samesite")):
            missing.append("SameSite")

        if not missing:
            findings.append(Finding(
                CHECK, Severity.INFO, f"Cookie '{c.name}' com flags adequadas",
                metadata={"cookie": c.name},
            ))
            continue
        severity = Severity.MEDIUM if "Secure" in missing else Severity.LOW
        findings.append(Finding(
            CHECK, severity, f"Cookie '{c.name}' sem flags: {', '.join(missing)}",
            f"O cookie {c.name} não define: {', '.join(missing)}.",
            "Defina Secure, HttpOnly e SameSite (Lax ou Strict) nos cookies.",
            {"cookie": c.name, "missing": missing},
        ))
    return findings
