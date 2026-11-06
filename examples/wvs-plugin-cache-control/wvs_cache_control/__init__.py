"""Example plugin: responses that set cookies should prevent shared caching.

Vulnerability: if a response with Set-Cookie (e.g. a session) can be stored by a proxy or CDN,
another user may receive the victim's session.
Ref.: OWASP WSTG-ATHN-06 (Browser Cache Weaknesses); CWE-524.
"""
from scanner.finding import Finding, Severity
from scanner.registry import CheckSpec


def check_cache_control(response) -> list:
    """"response" signature: receives the httpx response of the homepage and returns a list of Finding."""
    if not response.headers.get_list("set-cookie"):
        return [Finding("cache_control", Severity.INFO, "Response has no cookies: Cache-Control not applicable",
                        rule_id="cache_control.na")]
    cc = response.headers.get("cache-control", "").lower()
    if any(token in cc for token in ("no-store", "private")):
        return [Finding("cache_control", Severity.INFO, "Response with cookies prevents shared caching",
                        evidence=f"Cache-Control: {cc}", rule_id="cache_control.ok")]
    return [Finding(
        "cache_control", Severity.MEDIUM, "Response with Set-Cookie may be stored in a shared cache",
        "Without 'no-store' or 'private', a proxy/CDN can serve one user's session to another.",
        "Send 'Cache-Control: no-store' (or 'private') on responses that set cookies.",
        evidence=f"Cache-Control: {cc or 'missing'}", cwe="CWE-524", confidence="medium",
        rule_id="cache_control.shared-cache")]


SPEC = CheckSpec(
    name="cache_control", kind="response", func=check_cache_control, category="web",
    description="Responses with cookies should send Cache-Control: no-store/private.",
)
