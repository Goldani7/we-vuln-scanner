"""DNS hardening: CAA and DNSSEC (public DNS queries only).

- CAA restricts which certificate authorities may issue certificates for the domain. Without it any
  CA can, so a mis-issuance or a validation hijack at a lax CA yields a valid cert for your name.
- DNSSEC signs DNS answers so resolvers can detect forged records (cache poisoning/spoofing).
Both are hardening, not exploitable on their own: severity is LOW.
Ref.: RFC 8659 (CAA), RFC 4033 (DNSSEC); CWE-345.
"""
import asyncio
import ipaddress

import dns.exception
import dns.resolver

from ..finding import Finding, Severity
from .email_dns import _resolver

CHECK = "dns_security"


def _zone(resolver, domain: str) -> str:
    try:
        return str(dns.resolver.zone_for_name(domain, resolver=resolver)).rstrip(".")
    except dns.exception.DNSException:
        return domain


def _has(resolver, name: str, rtype: str):
    """True/False, or None when the lookup itself failed (we then say nothing)."""
    try:
        resolver.resolve(name, rtype)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except dns.exception.DNSException:
        return None


def check_dns_security_sync(domain: str, timeout: float = 5, resolver=None) -> list:
    try:
        ipaddress.ip_address(domain)
        return []
    except ValueError:
        pass
    resolver = resolver or _resolver(timeout)
    zone = _zone(resolver, domain)
    findings = []

    caa = _has(resolver, domain, "CAA")
    if caa is False:
        findings.append(Finding(
            CHECK, Severity.LOW, f"No CAA record for {domain}",
            "Any certificate authority may issue certificates for this domain.",
            'Publish a CAA record naming only the CAs you use, e.g. `0 issue "letsencrypt.org"`, '
            'plus `0 iodef "mailto:security@…"`.',
            {"domain": domain}, evidence=f"CAA {domain} → no records", cwe="CWE-295",
            confidence="high", rule_id="dns.no-caa", references=["https://www.rfc-editor.org/rfc/rfc8659"]))
    elif caa:
        findings.append(Finding(CHECK, Severity.INFO, "CAA record present", rule_id="dns.caa-ok"))

    ds = _has(resolver, zone, "DS")
    if ds is False:
        findings.append(Finding(
            CHECK, Severity.LOW, f"DNSSEC not enabled for {zone}",
            "There is no DS record at the parent zone, so DNS answers for this domain are not "
            "cryptographically signed and can be spoofed on the path to a resolver.",
            "Enable DNSSEC at your DNS provider and publish the DS record at your registrar.",
            {"zone": zone}, evidence=f"DS {zone} → no records", cwe="CWE-345", confidence="high",
            rule_id="dns.no-dnssec", references=["https://www.rfc-editor.org/rfc/rfc4033"]))
    elif ds:
        findings.append(Finding(CHECK, Severity.INFO, "DNSSEC enabled (DS record present)",
                                rule_id="dns.dnssec-ok"))
    return findings


async def check_dns_security(ctx) -> list:
    return await asyncio.to_thread(check_dns_security_sync, ctx.domain, ctx.config.timeout)
