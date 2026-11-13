"""Page-level HTML weaknesses found passively in the homepage (no extra requests).

- Mixed content: an https page loading scripts/styles/frames over http can be tampered with by a
  network attacker (active mixed content), or leak/alter media (passive).
- Missing SRI: a third-party <script>/<link rel=stylesheet> without `integrity` runs whatever the CDN
  serves tomorrow; a CDN compromise becomes a compromise of this site (Polyfill.io, 2024).
- Insecure login forms: a password field posted over plain http.
Ref.: OWASP A08:2021 (Software and Data Integrity Failures); CWE-319, CWE-353, CWE-829.
"""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from ..finding import Finding, Severity

CHECK = "html_security"
MAX_LISTED = 8


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.resources = []   # (tag, url, has_integrity, active)
        self.forms = []       # {"action": str, "password": bool}
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.resources.append((tag, a["src"], "integrity" in a, True))
        elif tag == "link" and a.get("href") and "stylesheet" in a.get("rel", "").lower():
            self.resources.append((tag, a["href"], "integrity" in a, True))
        elif tag in ("iframe", "embed", "object"):
            src = a.get("src") or a.get("data")
            if src:
                self.resources.append((tag, src, True, True))
        elif tag in ("img", "audio", "video", "source") and a.get("src"):
            self.resources.append((tag, a["src"], True, False))
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "password": False}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None and a.get("type", "").lower() == "password":
            self._form["password"] = True

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _list(items) -> str:
    shown = "\n".join(items[:MAX_LISTED])
    return shown + (f"\n… (+{len(items) - MAX_LISTED} more)" if len(items) > MAX_LISTED else "")


def check_html_security(response) -> list:
    if "html" not in response.headers.get("content-type", "html").lower():
        return []
    page = str(response.url)
    scheme, host = urlparse(page).scheme, (urlparse(page).hostname or "").lower()
    parser = _Collector()
    try:
        parser.feed(response.text[:500_000])
    except Exception:  # noqa: BLE001 - broken markup must never break the scan
        return []

    findings = []
    active_mixed, passive_mixed, no_sri = [], [], []
    for tag, raw, has_integrity, active in parser.resources:
        url = urljoin(page, raw)
        u = urlparse(url)
        if scheme == "https" and u.scheme == "http":
            (active_mixed if active else passive_mixed).append(f"<{tag}> {url}")
        if (tag in ("script", "link") and not has_integrity and u.scheme in ("http", "https")
                and (u.hostname or "").lower() not in ("", host)):
            no_sri.append(f"<{tag}> {url}")

    if active_mixed:
        findings.append(Finding(
            CHECK, Severity.MEDIUM, "Active mixed content: scripts/styles/frames loaded over http",
            "An https page loads code over plain http. A network attacker can replace it and run "
            "arbitrary JavaScript in the page (browsers usually block it, breaking the site).",
            "Serve every sub-resource over https (or use relative/https URLs) and add "
            "`Content-Security-Policy: upgrade-insecure-requests`.",
            {"resources": active_mixed}, evidence=_list(active_mixed), cwe="CWE-319",
            confidence="high", rule_id="html.mixed-content-active"))
    if passive_mixed:
        findings.append(Finding(
            CHECK, Severity.LOW, "Passive mixed content: images/media loaded over http",
            "Images or media load over http on an https page; they can be swapped or used to "
            "track the user.", "Serve them over https.", {"resources": passive_mixed},
            evidence=_list(passive_mixed), cwe="CWE-319", confidence="high",
            rule_id="html.mixed-content-passive"))
    if no_sri:
        findings.append(Finding(
            CHECK, Severity.LOW, f"{len(no_sri)} third-party resource(s) without Subresource Integrity",
            "Scripts/styles from other origins have no `integrity` hash, so a compromised CDN "
            "could inject code into this site.",
            'Add integrity="sha384-…" and crossorigin="anonymous", or self-host the files.',
            {"resources": no_sri}, evidence=_list(no_sri), cwe="CWE-829", confidence="high",
            rule_id="html.no-sri",
            references=["https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity"]))

    for form in parser.forms:
        if not form["password"]:
            continue
        action = urljoin(page, form["action"]) if form["action"] else page
        if urlparse(action).scheme == "http":
            findings.append(Finding(
                CHECK, Severity.HIGH, "Password form submits over plain http",
                "Credentials typed in this form travel unencrypted and can be sniffed or altered.",
                "Serve the page over https and point the form action to an https URL.",
                {"action": action}, evidence=f"<form action=\"{action}\"> with a password field",
                cwe="CWE-319", confidence="high", rule_id="html.insecure-form"))
    return findings
