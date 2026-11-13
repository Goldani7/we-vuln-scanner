"""Known-vulnerable front-end libraries, detected from the script URLs in the homepage.

Passive and offline: the version is read from the URL itself (`jquery-3.3.1.min.js`,
`/ajax/libs/lodash.js/4.17.4/…`, `bootstrap@3.3.7`), so the file is never downloaded. A version
that isn't in the URL is simply not detected (no guess).
Limitation: a deliberately small table of high-confidence entries. For complete coverage run
retire.js / OSV-Scanner / npm audit against the actual build.
Ref.: OWASP A06:2021 (Vulnerable and Outdated Components); CWE-1104.
"""
import re
from urllib.parse import urljoin, urlparse

from ..finding import Finding, Severity
from .html_security import _Collector

CHECK = "js_libs"


def _v(text: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", text))


# name -> (url regex for the name, [(min_inclusive, fixed_in)], severity, CVEs / reason)
LIBS = {
    "jQuery": (r"jquery(?:\.min)?", [("0", "3.5.0")], Severity.MEDIUM,
               "XSS in htmlPrefilter/DOM manipulation (CVE-2020-11022, CVE-2020-11023; CVE-2015-9251 "
               "before 3.0.0)"),
    "Bootstrap": (r"bootstrap(?:\.bundle)?(?:\.min)?", [("3.0.0", "3.4.1"), ("4.0.0", "4.3.1")],
                  Severity.MEDIUM, "XSS in tooltip/popover data attributes (CVE-2019-8331)"),
    "Lodash": (r"lodash(?:\.js|\.min)?", [("0", "4.17.21")], Severity.MEDIUM,
               "Prototype pollution and command injection (CVE-2019-10744, CVE-2020-8203, "
               "CVE-2021-23337)"),
    "Moment.js": (r"moment(?:\.min)?", [("0", "2.29.4")], Severity.MEDIUM,
                  "ReDoS and path traversal (CVE-2022-24785, CVE-2022-31129)"),
    "Handlebars": (r"handlebars(?:\.min|\.runtime)?", [("0", "4.7.7")], Severity.HIGH,
                   "Remote code execution via crafted templates (CVE-2021-23369)"),
    "AngularJS": (r"angular(?:\.min)?", [("1.0.0", "2.0.0")], Severity.MEDIUM,
                  "AngularJS 1.x reached end-of-life in Dec 2021 and no longer receives security fixes"),
}
_VERSION = r"[-/@.]v?(\d+\.\d+(?:\.\d+)?)"


def detect_libs(url: str) -> list:
    """[(library, version)] found in one script URL."""
    path = urlparse(url).path.lower()
    found = []
    for lib, (name_rx, *_rest) in LIBS.items():
        m = re.search(rf"(?<![a-z0-9]){name_rx}{_VERSION}", path) or \
            re.search(rf"/{name_rx.split('(')[0]}(?:\.js)?/v?(\d+\.\d+(?:\.\d+)?)/", path)
        if m:
            found.append((lib, m.group(1)))
    return found


def check_js_libs(response) -> list:
    if "html" not in response.headers.get("content-type", "html").lower():
        return []
    page = str(response.url)
    parser = _Collector()
    try:
        parser.feed(response.text[:500_000])
    except Exception:  # noqa: BLE001
        return []
    seen, findings = set(), []
    for tag, raw, _integrity, _active in parser.resources:
        if tag != "script":
            continue
        url = urljoin(page, raw)
        for lib, version in detect_libs(url):
            if (lib, version) in seen:
                continue
            seen.add((lib, version))
            _name, ranges, severity, why = LIBS[lib]
            if any(_v(lo) <= _v(version) < _v(fixed) for lo, fixed in ranges):
                fixed = next(f for lo, f in ranges if _v(lo) <= _v(version) < _v(f))
                findings.append(Finding(
                    CHECK, severity, f"Vulnerable {lib} {version} loaded by the page",
                    f"{lib} {version} is older than {fixed}: {why}.",
                    f"Upgrade {lib} to {fixed} or later (and rebuild/re-pin any bundled copy).",
                    {"library": lib, "version": version, "fixed_in": fixed, "url": url},
                    evidence=f"<script src=\"{url}\">", cwe="CWE-1104", confidence="medium",
                    rule_id=f"js.{lib.lower().replace('.', '')}"))
    return findings
