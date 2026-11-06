"""PASSIVE subdomain enumeration via Certificate Transparency (crt.sh).

Why: an organization's real attack surface is rarely the main domain; staging, admin, VPN and
forgotten services show up in public certificates. The query goes to crt.sh (not to the target),
so there's no brute-force and no traffic against the domain beyond resolving the names via DNS.
Example: "staging-api.company.com" shows up in a certificate and runs an old, unauthenticated version.
Ref.: RFC 6962 (Certificate Transparency); OWASP WSTG-INFO-04.
"""
import asyncio
import ipaddress
import json
import re
import socket

from ..finding import Finding, Severity
from ..http import RequestFailed

CHECK = "subdomains"
CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
MAX_RESOLVE = 200
RESOLVE_CONCURRENCY = 20
SENSITIVE_NAME = re.compile(
    r"(^|[.-])(dev|staging|stage|test|qa|uat|admin|internal|intranet|vpn|jenkins|gitlab|git|jira|"
    r"grafana|kibana|phpmyadmin|backup|old|beta|sandbox|demo|preprod)([.-]|\d|$)", re.I)


def parse_crtsh(payload, domain: str) -> list:
    """Unique names under `domain` extracted from crt.sh's JSON (wildcards normalized)."""
    names = set()
    for entry in payload if isinstance(payload, list) else []:
        for raw in str(entry.get("name_value", "")).splitlines():
            name = raw.strip().lower().lstrip("*.")
            if name != domain and name.endswith("." + domain) and re.fullmatch(r"[a-z0-9._-]+", name):
                names.add(name)
    return sorted(names)


async def resolve_many(names, concurrency: int = RESOLVE_CONCURRENCY, timeout: float = 5.0) -> dict:
    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_running_loop()

    async def one(name):
        async with sem:
            try:
                info = await asyncio.wait_for(
                    loop.getaddrinfo(name, None, type=socket.SOCK_STREAM), timeout)
                return name, sorted({i[4][0] for i in info})
            except (OSError, asyncio.TimeoutError):
                return name, []

    return dict(await asyncio.gather(*[one(n) for n in names]))


def _is_ip_or_local(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return "." not in host


async def check_subdomains(ctx) -> list:
    domain = ctx.domain
    if _is_ip_or_local(domain):
        return [Finding(CHECK, Severity.INFO, "Subdomain enumeration skipped",
                        f"'{domain}' is an IP or a local name, with no Certificate Transparency.",
                        rule_id="subdomains.skipped")]
    try:
        r = await ctx.client.request("GET", CRT_URL.format(domain=domain), timeout=30,
                                     follow_redirects=True)
        payload = json.loads(r.text) if r.status_code == 200 else None
    except (RequestFailed, ValueError) as e:
        payload, r = None, e
    if payload is None:
        reason = r.describe() if isinstance(r, RequestFailed) else (
            f"HTTP {r.status_code}" if hasattr(r, "status_code") else str(r))
        return [Finding(CHECK, Severity.INFO, "crt.sh unavailable; subdomains not enumerated",
                        f"Could not query crt.sh ({reason}). The service is known to be "
                        "unstable.", "Try again later.", rule_id="subdomains.unavailable")]

    names = parse_crtsh(payload, domain)
    if not names:
        return [Finding(CHECK, Severity.INFO, "No subdomains in Certificate Transparency",
                        f"crt.sh returned no certificates for subdomains of {domain}.",
                        rule_id="subdomains.none")]

    resolved = await resolve_many(names[:MAX_RESOLVE])
    live = {n: ips for n, ips in resolved.items() if ips}
    capped = f" (resolution limited to the first {MAX_RESOLVE})" if len(names) > MAX_RESOLVE else ""
    evidence = "\n".join(f"{n} → {', '.join(live[n])}" if n in live else f"{n} (does not resolve)"
                         for n in names[:40])
    if len(names) > 40:
        evidence += f"\n… (+{len(names) - 40})"
    findings = [Finding(
        CHECK, Severity.INFO, f"{len(names)} subdomains discovered via Certificate Transparency",
        f"{len(live)} resolve in DNS{capped}. Each one is attack surface worth reviewing.",
        "Inventory these hosts, decommission the ones no longer in use, and review the pentest scope.",
        {"subdomains": [{"name": n, "ips": resolved.get(n, [])} for n in names]},
        evidence=evidence, cwe="CWE-200", references=["https://crt.sh/"], confidence="high",
        rule_id="subdomains.discovered")]

    sensitive = [n for n in live if SENSITIVE_NAME.search(n[: -len(domain) - 1])]
    if sensitive:
        findings.append(Finding(
            CHECK, Severity.LOW, f"{len(sensitive)} internal/non-production subdomain(s) exposed",
            "Names like dev/staging/admin/vpn tend to have less hardening and real data.",
            "Restrict them by VPN/IP, require authentication, and remove DNS/certificates for "
            "decommissioned environments.",
            {"subdomains": sensitive}, evidence="\n".join(f"{n} → {', '.join(live[n])}" for n in sensitive[:20]),
            cwe="CWE-668", confidence="medium", rule_id="subdomains.sensitive-names"))

    private = {n: [ip for ip in ips if ipaddress.ip_address(ip).is_private]
               for n, ips in live.items()}
    private = {n: ips for n, ips in private.items() if ips}
    if private:
        findings.append(Finding(
            CHECK, Severity.LOW, f"{len(private)} public subdomain(s) point to private IPs",
            "Public DNS reveals the internal topology (RFC 1918) and can be used in DNS rebinding attacks.",
            "Move internal records to internal DNS (split-horizon).",
            {"subdomains": private}, evidence="\n".join(f"{n} → {', '.join(ips)}" for n, ips in list(private.items())[:20]),
            cwe="CWE-200", confidence="high", rule_id="subdomains.private-ip"))
    return findings
