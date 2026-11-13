"""Common server misconfigurations.

Vulnerabilities covered (all via ordinary requests, no attack payloads):
- HTTP with no redirect to HTTPS (credentials/sessions travel in the clear);
- TRACE method enabled (Cross-Site Tracing); write methods advertised in Allow;
- directory listing (leaks files and backups);
- error pages with a stack trace/debug info (leaks paths, versions and SQL queries);
- missing security.txt (RFC 9116), useful for responsible disclosure.
Example: /uploads/ with "Index of /uploads" lists dump.sql; a 500 error with a traceback reveals
the code's path and the framework's version, speeding up exploitation.
Ref.: OWASP A05:2021; CWE-548 (directory listing), CWE-209 (error message info leak), CWE-693.
"""
import asyncio
import re
import uuid
from urllib.parse import urljoin, urlparse

from ..finding import Finding, Severity
from ..http import RequestFailed

CHECK = "misconfig"
OWASP_A05 = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"

LISTING_PATHS = ["/", "/uploads/", "/backup/", "/backups/", "/files/", "/images/",
                 "/static/", "/assets/", "/logs/", "/tmp/"]
_LISTING = re.compile(
    r"<title>Index of /|<h1>Index of /|Directory listing for /|\[To Parent Directory\]|"
    r"<title>Directory Listing For", re.I)
_SENSITIVE_EXT = re.compile(r"\.(sql|bak|zip|tar|gz|env|log|old|key|pem|conf|ini)\b", re.I)

ERROR_SIGNATURES = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"Whitelabel Error Page", "Spring Boot's default error page"),
    (r"You're seeing this error because you have <code>DEBUG = True", "Django with DEBUG=True"),
    (r"Server Error in '/[^']*' Application", "detailed ASP.NET error"),
    (r"\bat [\w.$]+\([\w]+\.java:\d+\)", "Java stack trace"),
    (r"<b>(Warning|Fatal error|Notice)</b>:.{0,200} on line <b>\d+</b>", "PHP error with the file path"),
    (r"Whoops! There was an error|Symfony Exception|facade/ignition", "debug page (Laravel/Symfony)"),
    (r"You have an error in your SQL syntax|ORA-\d{5}|SQLSTATE\[\w+\]|PG::\w*Error", "database error"),
]


async def _get(ctx, path_or_url, method="GET", **kw):
    url = path_or_url if "://" in path_or_url else urljoin(ctx.url, path_or_url)
    try:
        return await ctx.client.request(method, url, **kw)
    except RequestFailed:
        return None


async def _https_redirect(ctx) -> list:
    p = urlparse(ctx.url)
    if p.scheme != "https" or p.port not in (None, 443):
        return []
    url = f"http://{p.hostname}/"
    r = await _get(ctx, url)
    if r is None:
        return []  # port 80 closed: nothing to report
    location = r.headers.get("location", "")
    if 300 <= r.status_code < 400 and location.lower().startswith("https://"):
        return [Finding(CHECK, Severity.INFO, "HTTP redirects to HTTPS",
                        evidence=f"GET {url} → {r.status_code} Location: {location}",
                        rule_id="misconfig.https-redirect-ok")]
    if r.status_code < 400:
        return [Finding(
            CHECK, Severity.MEDIUM, "HTTP does not redirect to HTTPS",
            "The site responds in plain text on port 80 with no redirect, allowing the first "
            "request (and any cookies without Secure) to be intercepted.",
            "Redirect all HTTP traffic to HTTPS (301) and enable HSTS.",
            evidence=f"GET {url} → HTTP {r.status_code}" + (f" Location: {location}" if location else ""),
            cwe="CWE-319", references=[OWASP_A05], confidence="high", rule_id="misconfig.no-https-redirect")]
    return []


async def _http_methods(ctx) -> list:
    findings = []
    opts = await _get(ctx, ctx.url, "OPTIONS", follow_redirects=True)
    allow = {m.strip().upper() for m in (opts.headers.get("allow", "") if opts else "").split(",") if m.strip()}

    trace = await _get(ctx, ctx.url, "TRACE", headers={"X-WVS-Probe": "trace-echo"})
    if trace is not None and trace.status_code == 200 and "trace-echo" in trace.text.lower():
        findings.append(Finding(
            CHECK, Severity.MEDIUM, "HTTP TRACE method enabled",
            "The server echoes the full request (Cross-Site Tracing), which can expose headers "
            "like proxy cookies/credentials in XSS scenarios.",
            "Disable TRACE (Apache: TraceEnable off; nginx does not support it by default).",
            evidence="TRACE returned 200 reflecting the X-WVS-Probe header",
            cwe="CWE-693", references=[OWASP_A05], confidence="high", rule_id="misconfig.trace"))
    risky = sorted(allow & {"PUT", "DELETE", "CONNECT"})
    if risky:
        findings.append(Finding(
            CHECK, Severity.LOW, f"Potentially dangerous methods advertised: {', '.join(risky)}",
            "The Allow header lists write methods. This only indicates configuration: the scanner "
            "never tries to modify anything, so verify it manually.",
            "Restrict the allowed methods to the minimum each route needs.",
            evidence=f"OPTIONS → Allow: {', '.join(sorted(allow))}",
            cwe="CWE-749", references=[OWASP_A05], confidence="low", rule_id="misconfig.methods"))
    return findings


async def _directory_listing(ctx) -> list:
    responses = await asyncio.gather(*[_get(ctx, p) for p in LISTING_PATHS])
    findings = []
    for path, r in zip(LISTING_PATHS, responses, strict=True):
        if r is None or r.status_code != 200 or not _LISTING.search(r.text[:20000]):
            continue
        names = re.findall(r'href="([^"?#]+)"', r.text)
        names = [n for n in names if not n.startswith(("/", "?", "http")) and n != "../"]
        sensitive = [n for n in names if _SENSITIVE_EXT.search(n)]
        findings.append(Finding(
            CHECK, Severity.HIGH if sensitive else Severity.MEDIUM,
            f"Directory listing enabled at {path}",
            "The server lists the directory's contents, making it easy to discover files that "
            "shouldn't be public." + (f" Sensitive files found: {', '.join(sensitive[:5])}." if sensitive else ""),
            "Disable the listing (Apache: Options -Indexes; nginx: autoindex off) and remove "
            "files that shouldn't be public.",
            {"path": path, "entries": names[:50]},
            evidence="Entries: " + (", ".join(names[:8]) or "(none extracted)"),
            cwe="CWE-548", references=[OWASP_A05], confidence="high", rule_id="misconfig.dir-listing"))
    return findings


async def _error_disclosure(ctx) -> list:
    bodies = []
    try:
        bodies.append(("homepage", (await ctx.index()).text[:50000]))
    except RequestFailed:
        pass
    miss = await _get(ctx, f"/{uuid.uuid4().hex}")
    if miss is not None:
        bodies.append(("response to a nonexistent path", miss.text[:50000]))
    findings, seen = [], set()
    for where, text in bodies:
        for pattern, label in ERROR_SIGNATURES:
            m = re.search(pattern, text, re.I | re.S)
            if m and label not in seen:
                seen.add(label)
                snippet = re.sub(r"\s+", " ", text[max(0, m.start() - 40): m.end() + 80]).strip()
                findings.append(Finding(
                    CHECK, Severity.MEDIUM, f"Information disclosure in an error: {label}",
                    f"The {where} contains internal details ({label}), useful to an attacker.",
                    "Disable debug mode in production and use generic error pages; log details "
                    "only internally.",
                    evidence=snippet[:200], cwe="CWE-209", references=[OWASP_A05],
                    confidence="high", rule_id="misconfig.error-disclosure"))
    return findings


async def _security_txt(ctx) -> list:
    r = await _get(ctx, "/.well-known/security.txt")
    if r is not None and r.status_code == 200 and "contact:" in r.text.lower():
        return [Finding(CHECK, Severity.INFO, "security.txt present",
                        evidence=r.text[:200], rule_id="misconfig.security-txt-ok")]
    return [Finding(CHECK, Severity.INFO, "security.txt missing",
                    "Without /.well-known/security.txt, researchers don't know how to report issues.",
                    "Publish a security.txt (RFC 9116) with Contact and Expires.",
                    rule_id="misconfig.security-txt-missing", confidence="high")]


async def check_misconfig(ctx) -> list:
    results = await asyncio.gather(
        _https_redirect(ctx), _http_methods(ctx), _directory_listing(ctx),
        _error_disclosure(ctx), _security_txt(ctx))
    return [f for group in results for f in group]
