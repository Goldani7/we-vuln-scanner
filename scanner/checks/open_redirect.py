"""Open redirect (ACTIVE check: only runs with --allow-active and inside --scope).

Vulnerability: an endpoint that redirects to a URL taken from a parameter lets an attacker craft a
link on YOUR domain that bounces victims to a phishing site (and defeats OAuth redirect allowlists).
Method: GET with a redirect-style parameter (next, url, redirect…) set to an external, harmless
host that doesn't exist (`.test` TLD), without following redirects, and look at the Location header.
Candidates come from a short list of common names on `/` plus the redirect-like parameters already
present in links of the homepage. Nothing is submitted, no state is changed, at most ~30 GETs.
Ref.: OWASP WSTG-CLNT-04; CWE-601.
"""
import html as htmllib
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from ..finding import Finding, Severity
from ..http import RequestFailed

CHECK = "open_redirect"
PROBE_HOST = "wvs-open-redirect-probe.test"
PARAMS = ("next", "url", "redirect", "redirect_uri", "redirect_url", "return", "returnUrl",
          "return_to", "continue", "dest", "destination", "redir", "r", "goto", "target")
_REDIRECT_PARAM = re.compile(r"^(" + "|".join(PARAMS) + r")$", re.I)
MAX_PROBES = 30


def _candidates(base: str, page: str) -> list:
    """URLs to probe: (path "/" x common params) + homepage links that already carry such a param."""
    probe = f"https://{PROBE_HOST}/"
    host = urlparse(base).hostname
    seen, out = set(), []

    def add(url):
        if url not in seen:
            seen.add(url)
            out.append(url)

    for href in re.findall(r'href=["\']([^"\']+)["\']', page[:200_000], re.I):
        u = urlparse(urljoin(base, htmllib.unescape(href)))
        if u.hostname != host:
            continue
        pairs = parse_qsl(u.query, keep_blank_values=True)
        if any(_REDIRECT_PARAM.match(k) for k, _ in pairs):
            query = urlencode([(k, probe if _REDIRECT_PARAM.match(k) else v) for k, v in pairs])
            add(urlunparse(u._replace(query=query, fragment="")))
    for p in PARAMS:
        add(urljoin(base, "/") + "?" + urlencode({p: probe}))
    return out[:MAX_PROBES]


def _redirects_to_probe(response, url: str) -> bool:
    if not 300 <= response.status_code < 400:
        return False
    loc = response.headers.get("location", "")
    return (urlparse(urljoin(url, loc)).hostname or "").lower() == PROBE_HOST


async def check_open_redirect(ctx) -> list:
    try:
        index_text = (await ctx.index()).text
    except RequestFailed:
        index_text = ""
    vulnerable = []
    for url in _candidates(ctx.url, index_text):
        try:
            r = await ctx.client.request("GET", url, follow_redirects=False, retries=0)
        except RequestFailed as e:
            if e.kind == "out_of_scope":
                break
            continue
        if _redirects_to_probe(r, url):
            vulnerable.append((url, r.status_code, r.headers.get("location", "")))
    if not vulnerable:
        return [Finding(CHECK, Severity.INFO, "No open redirect found among the tested parameters",
                        rule_id="redirect.none")]
    return [Finding(
        CHECK, Severity.MEDIUM, f"Open redirect via '{parse_qsl(urlparse(u).query)[0][0]}' parameter",
        "The server redirects to an arbitrary external URL taken from the query string. "
        "Attackers use it to make phishing links look like they belong to this domain.",
        "Only redirect to relative paths or to an allowlist of known destinations; never "
        "to a user-supplied absolute URL.",
        {"url": u, "status": status, "location": loc}, evidence=f"GET {u} → {status} Location: {loc}",
        cwe="CWE-601", confidence="high", rule_id="redirect.open",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"])
        for u, status, loc in vulnerable]
