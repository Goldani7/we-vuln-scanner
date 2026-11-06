"""ACTIVE WAF probe (active check: only runs with --allow-active and inside --scope).

Method: besides the baseline (a normal GET, already fetched by the scan), sends ONE extra
request with a query parameter holding a generic, well-known WAF test pattern (path-traversal
style), used by fingerprinting tools like wafw00f. It's not a functional payload: it's just a
"suspicious" string to see whether the WAF reacts, sent in a parameter (`wvs_probe`) the
application shouldn't process. No data is changed, no exploitation is attempted.
Why: many WAFs only reveal themselves by blocking something. Passive detection (`waf.py`) misses
those cases; this probe confirms active presence and, when it gets blocked, tries to identify
the vendor using the same signature table as the passive module.
Ref.: technique used by wafw00f; OWASP WSTG-INFO-02.
"""
from urllib.parse import urlsplit, urlunsplit

from ..finding import Finding, Severity
from ..http import RequestFailed
from .waf import BLOCK_STATUSES, detect

CHECK = "waf_active"
PROBE_PARAM = "wvs_probe"
PROBE_VALUE = "../../../../etc/passwd"
REFERENCE = "https://github.com/EnableSecurity/wafw00f"


def _probe_url(url: str) -> str:
    parts = urlsplit(url)
    query = f"{parts.query}&{PROBE_PARAM}={PROBE_VALUE}" if parts.query else f"{PROBE_PARAM}={PROBE_VALUE}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _vendor_names(response) -> list:
    return [sig.name for sig, _hits in detect(response)]


async def check_waf_active(ctx) -> list:
    try:
        baseline = await ctx.index()
    except RequestFailed as e:
        return [Finding(CHECK, Severity.INFO, "Active WAF probe not run: baseline unavailable",
                        e.describe(), rule_id="waf_active.no-baseline")]

    if baseline.status_code in BLOCK_STATUSES:
        return [Finding(
            CHECK, Severity.INFO, "Active WAF probe is not conclusive",
            f"The baseline response itself already came back blocked (HTTP {baseline.status_code}); "
            "there's no way to tell normal blocking apart from the one the probe caused.",
            rule_id="waf_active.inconclusive")]

    try:
        probe = await ctx.client.request("GET", _probe_url(ctx.url), follow_redirects=True)
    except RequestFailed as e:
        return [Finding(CHECK, Severity.INFO, "Active WAF probe failed", e.describe(),
                        rule_id="waf_active.error")]

    evidence = (f"Baseline: GET {ctx.url} → HTTP {baseline.status_code}\n"
               f"Probe: GET {ctx.url}?{PROBE_PARAM}=<path traversal> → HTTP {probe.status_code}")
    if probe.status_code not in BLOCK_STATUSES:
        return [Finding(
            CHECK, Severity.INFO, "Active probe observed no blocking", evidence,
            "This doesn't prove the absence of a WAF: it may not react to this specific pattern, "
            "or may only act on other attack classes.",
            rule_id="waf_active.no-block", confidence="low")]

    vendors = _vendor_names(probe)
    detail = ("The server blocked a request with a suspicious pattern (path traversal) but not "
             "the normal request, confirming an active WAF." +
             (f" Vendor identified from the block response: {', '.join(vendors)}." if vendors else ""))
    return [Finding(
        CHECK, Severity.INFO, f"Active WAF confirmed{' (' + vendors[0] + ')' if vendors else ''}",
        detail, "No action needed: this is a confirmation, not a vulnerability. Other checks' "
        "results may be filtered by the WAF.",
        {"vendors": vendors, "probe_status": probe.status_code, "baseline_status": baseline.status_code},
        evidence=evidence, references=[REFERENCE], confidence="high", rule_id="waf_active.confirmed")]
