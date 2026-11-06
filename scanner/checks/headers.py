"""HTTP security headers, evaluating the VALUE and not just the presence.

Vulnerability: without CSP/X-Frame-Options/HSTS the browser has no instructions to block XSS,
clickjacking, or an HTTP downgrade. A header that's present but weak (CSP with 'unsafe-inline',
HSTS with a short max-age) gives a false sense of security.
Example: without X-Frame-Options/frame-ancestors, an attacker embeds the site in an invisible
<iframe> and tricks the user into clicking buttons (clickjacking).
Ref.: OWASP Secure Headers Project; OWASP A05:2021 (Security Misconfiguration); CWE-693.
"""
import re

from ..finding import Finding, Severity

CHECK = "headers"
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
HSTS_MIN_AGE = 15552000  # 180 days


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
        detail = "The response does not contain a Content-Security-Policy."
        if report_only:
            detail += " Only a Content-Security-Policy-Report-Only is present, which blocks nothing."
        return [_f("csp-missing", Severity.MEDIUM, f"Header {name} missing", detail,
                   "Set a restrictive CSP (e.g. default-src 'self'; object-src 'none'; "
                   "base-uri 'self'; frame-ancestors 'self'). Start in Report-Only to test it.",
                   name, evidence="missing", cwe="CWE-1021")]
    d = _directives(value)
    script = d.get("script-src", d.get("default-src", []))
    issues = []
    if "'unsafe-inline'" in script and not any(t.startswith(("'nonce-", "'sha")) for t in script):
        issues.append((Severity.MEDIUM, "unsafe-inline",
                       "script-src allows 'unsafe-inline', nullifying XSS protection."))
    if "'unsafe-eval'" in script:
        issues.append((Severity.LOW, "unsafe-eval", "script-src allows 'unsafe-eval'."))
    if any(t in ("*", "data:", "http:", "https:") for t in script):
        issues.append((Severity.MEDIUM, "wildcard-source",
                       "script-src accepts broad sources (*, data:, http: or https:), allowing "
                       "scripts to be loaded from any origin."))
    if "default-src" not in d:
        if "object-src" not in d:
            issues.append((Severity.LOW, "no-object-src", "No object-src or default-src: plugins are unrestricted."))
        if "base-uri" not in d:
            issues.append((Severity.LOW, "no-base-uri", "No base-uri: a <base> injection can redirect relative URLs."))
    if not issues:
        return [_f("csp-ok", Severity.INFO, f"Header {name} present", value[:300], "", name, evidence=value[:300])]
    return [
        _f(f"csp-{rule}", sev, f"Weak CSP: {rule}", msg,
           "Remove insecure directives; use nonces/hashes instead of 'unsafe-inline' and list "
           "explicit origins.", name, evidence=f"{name}: {value[:300]}")
        for sev, rule, msg in issues
    ]


def _hsts(headers, is_https: bool) -> list:
    name = "Strict-Transport-Security"
    value = headers.get(name)
    if not is_https:
        return []  # HSTS only applies over HTTPS; over HTTP the browser ignores the header
    if not value:
        return [_f("hsts-missing", Severity.MEDIUM, f"Header {name} missing",
                   "Without HSTS the browser accepts the first request over HTTP, allowing "
                   "downgrade and interception (sslstrip).",
                   "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                   name, evidence="missing", cwe="CWE-319")]
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    if not m:
        return [_f("hsts-invalid", Severity.LOW, "HSTS without a valid max-age", f"{name}: {value}",
                   "Set max-age (e.g. 31536000).", name, evidence=f"{name}: {value}", cwe="CWE-319")]
    age = int(m.group(1))
    out = []
    if age < HSTS_MIN_AGE:
        out.append(_f("hsts-short", Severity.LOW, f"HSTS with a short max-age ({age}s)",
                      f"max-age of {age}s (< 180 days) shortens the protection window.",
                      "Use a max-age of at least 31536000 (1 year).", name,
                      evidence=f"{name}: {value}", cwe="CWE-319"))
    if "includesubdomains" not in value.lower():
        out.append(_f("hsts-no-subdomains", Severity.LOW, "HSTS without includeSubDomains",
                      "Subdomains remain reachable over HTTP and can be used to steal cookies.",
                      "Add includeSubDomains (after confirming every subdomain supports HTTPS).",
                      name, evidence=f"{name}: {value}", cwe="CWE-319"))
    return out or [_f("hsts-ok", Severity.INFO, f"Header {name} present", value, "", name, evidence=value)]


def _xfo(headers, csp_value) -> list:
    name = "X-Frame-Options"
    value = headers.get(name)
    has_frame_ancestors = bool(csp_value and "frame-ancestors" in csp_value.lower())
    if not value:
        if has_frame_ancestors:
            return [_f("xfo-covered", Severity.INFO, f"Header {name} missing (covered by frame-ancestors)",
                       "The CSP defines frame-ancestors, which supersedes X-Frame-Options.", "", name)]
        return [_f("xfo-missing", Severity.MEDIUM, f"Header {name} missing",
                   "No protection against clickjacking: the page can be embedded in iframes from "
                   "any site.",
                   "Use 'X-Frame-Options: DENY' or SAMEORIGIN, or CSP frame-ancestors.",
                   name, evidence="missing (and no frame-ancestors in the CSP)", cwe="CWE-1021")]
    v = value.strip().upper()
    if v in ("DENY", "SAMEORIGIN"):
        return [_f("xfo-ok", Severity.INFO, f"Header {name} present", value, "", name, evidence=value)]
    return [_f("xfo-invalid", Severity.LOW, f"{name} has an invalid or obsolete value",
               f"Value '{value}': ALLOW-FROM is not supported by modern browsers.",
               "Use DENY/SAMEORIGIN or CSP frame-ancestors.", name,
               evidence=f"{name}: {value}", cwe="CWE-1021")]


def _simple(headers, name, rule, ok, missing_sev, missing_msg, remediation, bad_msg=None) -> list:
    value = headers.get(name)
    if not value:
        return [_f(f"{rule}-missing", missing_sev, f"Header {name} missing", missing_msg,
                   remediation, name, evidence="missing")]
    if ok(value):
        return [_f(f"{rule}-ok", Severity.INFO, f"Header {name} present", value, "", name, evidence=value)]
    return [_f(f"{rule}-weak", Severity.LOW, f"{name} has a weak value", bad_msg or f"Value: {value}",
               remediation, name, evidence=f"{name}: {value}")]


def _info_disclosure(headers) -> list:
    out = []
    for name in ("X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        value = headers.get(name)
        if value:
            out.append(_f(f"leak-{name.lower()}", Severity.LOW, f"Header {name} exposes technology",
                          f"{name}: {value}", f"Remove the {name} header from the response.", name,
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
        "Without nosniff the browser may interpret a wrong-MIME file as a script.",
        "Add 'X-Content-Type-Options: nosniff'.", "Value must be exactly 'nosniff'.")
    findings += _simple(
        h, "Referrer-Policy", "referrer",
        lambda v: v.strip().lower() not in ("unsafe-url", "no-referrer-when-downgrade", ""),
        Severity.LOW, "Full URLs (with tokens/IDs) can leak to third parties via the Referer header.",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
        "This policy sends the full URL to third parties.")
    for name, why in (
        ("Permissions-Policy", "restricts browser APIs (camera, geolocation...)"),
        ("Cross-Origin-Opener-Policy", "isolates the window against cross-origin attacks (XS-Leaks)"),
        ("Cross-Origin-Resource-Policy", "prevents other sites from loading your resources"),
    ):
        if h.get(name):
            findings.append(_f(name.lower(), Severity.INFO, f"Header {name} present", h[name], "", name, evidence=h[name]))
        else:
            findings.append(_f(f"{name.lower()}-missing", Severity.INFO, f"Header {name} missing",
                               f"Optional, but it {why}.", f"Consider setting {name}.", name, evidence="missing"))
    findings += _info_disclosure(h)
    return findings
