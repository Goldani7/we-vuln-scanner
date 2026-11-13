"""Subdomain takeover: dangling CNAME records (passive, DNS only).

Vulnerability: `shop.example.com CNAME example.azurewebsites.net` keeps working in DNS after the
Azure app is deleted. Anyone can then register that name on the provider and serve their own
content (phishing, cookie theft on the parent domain) from a subdomain of the victim.
How it's detected here: subdomains come from Certificate Transparency (shared with the `subdomains`
check); for each CNAME we resolve the target. If the target no longer exists (NXDOMAIN) the record
dangles. No HTTP request is sent to the subdomain, so this stays passive.
Limitation: providers that keep resolving after deletion (GitHub Pages, S3 website endpoints,
Heroku) need an HTTP fingerprint and are NOT detected here.
Ref.: OWASP WSTG-CONF-10; CWE-1327 / CWE-350.
"""
import asyncio

import dns.exception
import dns.resolver

from ..finding import Finding, Severity
from .email_dns import _resolver
from .subdomains import MAX_RESOLVE, fetch_ct_names

CHECK = "subdomain_takeover"
CONCURRENCY = 20
# Providers where deleting the resource removes the DNS name, so NXDOMAIN really means "claimable".
CLAIMABLE_SUFFIXES = (
    ".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net",
    ".blob.core.windows.net", ".azureedge.net", ".azure-api.net", ".elasticbeanstalk.com",
    ".cloudfront.net", ".herokudns.com",
)


def inspect_cname(resolver, name: str):
    """None if `name` has no CNAME or its target resolves; else (target, claimable_provider)."""
    try:
        answer = resolver.resolve(name, "CNAME")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.exception.DNSException):
        return None
    target = str(answer[0].target).rstrip(".").lower()
    try:
        resolver.resolve(target, "A")
        return None
    except dns.resolver.NXDOMAIN:
        return target, target.endswith(CLAIMABLE_SUFFIXES)
    except dns.exception.DNSException:
        return None  # NoAnswer (e.g. IPv6-only), timeout, SERVFAIL: not evidence of a dangling record


async def find_dangling(names, resolver, concurrency: int = CONCURRENCY) -> list:
    sem = asyncio.Semaphore(concurrency)

    async def one(name):
        async with sem:
            res = await asyncio.to_thread(inspect_cname, resolver, name)
            return (name, *res) if res else None

    return [r for r in await asyncio.gather(*[one(n) for n in names]) if r]


async def check_subdomain_takeover(ctx, resolver=None) -> list:
    names, reason = await fetch_ct_names(ctx)
    if names is None:
        return [Finding(CHECK, Severity.INFO, "Subdomain takeover check skipped",
                        f"The subdomain list is unavailable ({reason}).",
                        rule_id="takeover.unavailable")]
    resolver = resolver or _resolver(ctx.config.timeout)
    dangling = await find_dangling(names[:MAX_RESOLVE], resolver)
    findings = []
    for name, target, claimable in dangling:
        findings.append(Finding(
            CHECK, Severity.HIGH if claimable else Severity.MEDIUM,
            f"Dangling CNAME: {name} → {target} (does not exist)",
            "The subdomain points to a name that no longer exists. "
            + ("This provider lets anyone re-register that name, so the subdomain can be taken over."
               if claimable else "If the target domain/resource can be registered by a third party, "
               "the subdomain can be taken over."),
            "Delete the DNS record, or re-create the resource at the provider. Audit DNS whenever a "
            "cloud resource is decommissioned.",
            {"subdomain": name, "cname": target, "claimable_provider": claimable},
            evidence=f"{name} CNAME {target} → NXDOMAIN", cwe="CWE-350",
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"],
            confidence="high" if claimable else "medium", rule_id="takeover.dangling-cname"))
    if not findings:
        findings.append(Finding(CHECK, Severity.INFO, "No dangling CNAME among the known subdomains",
                                f"{min(len(names), MAX_RESOLVE)} subdomain(s) checked.",
                                rule_id="takeover.none"))
    return findings
