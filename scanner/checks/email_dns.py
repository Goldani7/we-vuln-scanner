"""Email security and domain reputation: SPF, DKIM, DMARC and DNSBL.

Vulnerability: without SPF/DKIM/DMARC any server can send email on behalf of the domain,
making phishing and fraud (BEC) easier.
Example: without DMARC at p=reject, an attacker sends "ceo@domain.com" asking for a wire
transfer, and the recipient's server has no instruction to discard the forged message.
Ref.: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC); MITRE ATT&CK T1566 (Phishing).
Note: public DNS queries only; no email is ever sent.
"""
import ipaddress
import logging
import re

import dns.exception
import dns.resolver

from ..finding import Finding, Severity

log = logging.getLogger(__name__)

# Common DKIM selectors. DKIM has no way to list selectors: only known names can be tested, so
# no result ever proves DKIM doesn't exist.
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
    "s1", "s2", "smtp", "mandrill", "mxvault", "zoho", "protonmail",
]

# DNSBL zones queried. All of them accept free, low-volume queries.
IP_BLACKLISTS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]
DOMAIN_BLACKLISTS = ["dbl.spamhaus.org"]
MAX_MAIL_IPS = 5

_SPF_MECHANISM = re.compile(
    r"^[+\-~?]?(all|include:\S+|a(:\S+)?(/\d+)?|mx(:\S+)?(/\d+)?|ptr(:\S+)?|"
    r"ip4:\S+|ip6:\S+|exists:\S+)$", re.IGNORECASE)
_SPF_MODIFIER = re.compile(r"^(redirect|exp)=\S+$", re.IGNORECASE)
_SPF_LOOKUP_TERMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def _resolver(timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _query(resolver, name: str, rtype: str) -> list:
    """DNS query that returns [] when the name doesn't exist or has no such record.

    Timeouts and resolution failures propagate as dns.exception.DNSException for the caller to
    decide how to report them (a missing record differs from DNS being unavailable).
    """
    try:
        return list(resolver.resolve(name, rtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []


def _txt_records(resolver, name: str) -> list:
    """TXT records as strings (the 255-byte chunks of each record are concatenated)."""
    return [b"".join(r.strings).decode("utf-8", "replace") for r in _query(resolver, name, "TXT")]


def _dns_failure(check: str, name: str, err: Exception) -> Finding:
    return Finding(
        check, Severity.INFO, f"DNS query failed for {name}",
        f"{type(err).__name__}: {err}",
        "Check DNS connectivity/resolution and run again.",
    )


# --------------------------------------------------------------------------- SPF

def _spf_lookup_count(terms) -> int:
    count = 0
    for t in terms:
        bare = t.lstrip("+-~?").lower()
        if bare.startswith(("include:", "exists:", "redirect=", "ptr")) or re.match(r"^(a|mx)(:|/|$)", bare):
            count += 1
    return count


def check_spf(domain: str, timeout: float = 5, resolver=None) -> list:
    check = "spf"
    resolver = resolver or _resolver(timeout)
    try:
        records = [t for t in _txt_records(resolver, domain) if t.lower().startswith("v=spf1")]
    except dns.exception.DNSException as e:
        return [_dns_failure(check, domain, e)]

    if not records:
        return [Finding(
            check, Severity.HIGH, "Missing SPF record",
            f"{domain} does not publish a TXT starting with 'v=spf1'.",
            "Publish an SPF listing the authorized servers and ending in -all "
            "(e.g. 'v=spf1 include:_spf.your-provider.com -all').",
        )]
    if len(records) > 1:
        return [Finding(
            check, Severity.HIGH, "Multiple SPF records",
            f"{len(records)} SPF records found; RFC 7208 requires exactly one "
            "(the result is permerror and SPF is ignored).",
            "Merge the records into a single one.", {"records": records},
        )]

    record = records[0]
    terms = record.split()[1:]
    findings = [Finding(check, Severity.INFO, "SPF record present", record, metadata={"record": record})]

    invalid = [t for t in terms if not (_SPF_MECHANISM.match(t) or _SPF_MODIFIER.match(t))]
    if invalid:
        findings.append(Finding(
            check, Severity.MEDIUM, "Suspicious SPF syntax",
            f"Unrecognized terms: {', '.join(invalid)}.",
            "Fix the syntax; recipients may treat the whole record as an error.",
            {"terms": invalid},
        ))

    all_term = next((t for t in terms if t.lstrip("+-~?").lower() == "all"), None)
    policy = {
        "-all": (Severity.INFO, "SPF with -all (hard fail)", ""),
        "~all": (Severity.LOW, "SPF with ~all (soft fail)",
                 "Migrate to -all once every legitimate sender is listed."),
        "?all": (Severity.MEDIUM, "SPF with ?all (neutral)",
                 "?all offers no protection against spoofing; use -all or ~all."),
        "+all": (Severity.HIGH, "SPF with +all (authorizes any server)",
                 "Replace +all with -all: as it stands, anyone can spoof the domain."),
        "all": (Severity.HIGH, "SPF with 'all' (equivalent to +all)",
                "Replace it with -all."),
    }
    if all_term is None and not any(t.lower().startswith("redirect=") for t in terms):
        findings.append(Finding(
            check, Severity.MEDIUM, "SPF has no final 'all' mechanism",
            "Without 'all' (or redirect=), unlisted senders get a neutral result.",
            "End the record with -all.",
        ))
    elif all_term is not None:
        sev, title, rec = policy[all_term.lower()]
        findings.append(Finding(check, sev, title, f"Record terminator: {all_term}", rec))

    lookups = _spf_lookup_count(terms)
    if lookups > 10:
        findings.append(Finding(
            check, Severity.MEDIUM, "SPF exceeds the 10 DNS lookup limit",
            f"Estimated {lookups} lookup-generating mechanisms (RFC 7208 limit: 10).",
            "Reduce includes or use 'flattening'; above the limit SPF fails with permerror.",
            {"lookups": lookups},
        ))
    return findings


# -------------------------------------------------------------------------- DKIM

def check_dkim(domain: str, timeout: float = 5, resolver=None, selectors=None) -> list:
    check = "dkim"
    resolver = resolver or _resolver(timeout)
    found, revoked, errors = [], [], 0
    for sel in selectors or DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        try:
            txts = _txt_records(resolver, name)
        except dns.exception.DNSException as e:
            log.debug("DKIM %s: %s", name, e)
            errors += 1
            continue
        for txt in txts:
            if "p=" in txt.replace(" ", "").lower() or txt.lower().startswith("v=dkim1"):
                (revoked if re.search(r"\bp=\s*(;|$)", txt) else found).append(sel)
                break

    findings = []
    if found:
        findings.append(Finding(
            check, Severity.INFO, f"DKIM published ({len(found)} selector(s))",
            f"Selectors found: {', '.join(found)}.", metadata={"selectors": found},
        ))
    tested = len(selectors or DKIM_SELECTORS)
    if revoked and not found and len(revoked) == tested:
        # Wildcard '*._domainkey' with an empty p=: a recommended practice for domains that don't send email.
        return [Finding(
            check, Severity.INFO, "DKIM explicitly disabled (empty keys)",
            "Every selector tested returns an empty key (p=), typical of a wildcard on a domain "
            "that doesn't send email.", metadata={"selectors": revoked},
        )]
    if revoked:
        findings.append(Finding(
            check, Severity.LOW, "Revoked DKIM key (empty p=)",
            f"Selectors with an empty key: {', '.join(revoked)}.",
            "Remove old selectors, or publish a valid key if they're still in use.",
            {"selectors": revoked},
        ))
    if not found and not revoked:
        if errors == len(selectors or DKIM_SELECTORS):
            return [_dns_failure(check, domain, RuntimeError("every query failed"))]
        findings.append(Finding(
            check, Severity.LOW, "No standard DKIM selector found",
            f"Tested {len(selectors or DKIM_SELECTORS)} common selectors. This is not conclusive: "
            "the domain may use a custom selector.",
            "Confirm with the email provider and sign messages with DKIM.",
        ))
    return findings


# ------------------------------------------------------------------------- DMARC

def check_dmarc(domain: str, timeout: float = 5, resolver=None) -> list:
    check = "dmarc"
    resolver = resolver or _resolver(timeout)
    name = f"_dmarc.{domain}"
    try:
        records = [t for t in _txt_records(resolver, name) if t.lower().startswith("v=dmarc1")]
    except dns.exception.DNSException as e:
        return [_dns_failure(check, name, e)]

    if not records:
        return [Finding(
            check, Severity.HIGH, "Missing DMARC record",
            f"No TXT 'v=DMARC1' at {name}.",
            "Publish DMARC starting at p=none with rua= to collect reports, and evolve "
            "to quarantine and then reject.",
        )]

    record = records[0]
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p", "").lower()
    findings = [Finding(check, Severity.INFO, "DMARC record present", record,
                        metadata={"record": record, "policy": policy})]

    table = {
        "none": (Severity.MEDIUM, "DMARC policy p=none (monitoring only)",
                 "p=none does not block spoofed email; evolve to quarantine/reject."),
        "quarantine": (Severity.LOW, "DMARC policy p=quarantine",
                       "Consider p=reject once reports show only legitimate traffic."),
        "reject": (Severity.INFO, "DMARC policy p=reject", ""),
    }
    if policy in table:
        sev, title, rec = table[policy]
        findings.append(Finding(check, sev, title, f"p={policy}", rec))
    else:
        findings.append(Finding(
            check, Severity.MEDIUM, "Invalid or missing DMARC policy",
            f"Tag p= is missing or has an unknown value ({policy!r}); recipients ignore the record.",
            "Set p=none, quarantine or reject.",
        ))

    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject"):
        findings.append(Finding(
            check, Severity.LOW, f"DMARC applied to only {pct}% of messages",
            f"pct={pct}", "Raise it to pct=100 once the testing phase is over.",
        ))
    if "rua" not in tags:
        findings.append(Finding(
            check, Severity.LOW, "DMARC has no report address (rua)",
            "Without rua= you get no aggregate reports about who sends email as this domain.",
            "Add rua=mailto:dmarc@your-domain.",
        ))
    return findings


# ------------------------------------------------------------------------- DNSBL

def _mail_ips(resolver, domain: str) -> list:
    """IPv4 of the domain's mail servers (MX); with no MX, falls back to the domain's own A record."""
    hosts = [str(r.exchange).rstrip(".") for r in _query(resolver, domain, "MX")] or [domain]
    ips = []
    for host in hosts:
        if host == "":  # null MX (RFC 7505)
            continue
        try:
            ips.extend(str(r) for r in _query(resolver, host, "A"))
        except dns.exception.DNSException as e:
            log.debug("A %s: %s", host, e)
    return list(dict.fromkeys(ips))[:MAX_MAIL_IPS]


def _dnsbl_listed(resolver, query_name: str):
    """127.x.x.x return code if listed; None if not listed.

    Raises DNSException on a query failure. 127.255.255.x responses (Spamhaus) indicate an
    error/blocked resolver rather than a real listing, so they're treated as a failure.
    """
    answers = _query(resolver, query_name, "A")
    if not answers:
        return None
    code = str(answers[0])
    if code.startswith("127.255.255."):
        raise dns.exception.DNSException(f"DNSBL refused the query ({code}); public resolver blocked?")
    return code


def check_dnsbl(domain: str, timeout: float = 5, resolver=None) -> list:
    check = "dnsbl"
    resolver = resolver or _resolver(timeout)
    try:
        ips = _mail_ips(resolver, domain)
    except dns.exception.DNSException as e:
        return [_dns_failure(check, domain, e)]

    queries = [(f"{domain}", f"{domain}.{zone}", zone) for zone in DOMAIN_BLACKLISTS]
    for ip in ips:
        if ipaddress.ip_address(ip).version == 4:
            rev = ".".join(reversed(ip.split(".")))
            queries += [(ip, f"{rev}.{zone}", zone) for zone in IP_BLACKLISTS]

    findings, failures = [], 0
    for subject, qname, zone in queries:
        try:
            code = _dnsbl_listed(resolver, qname)
        except dns.exception.DNSException as e:
            log.debug("DNSBL %s: %s", qname, e)
            failures += 1
            continue
        if code:
            findings.append(Finding(
                check, Severity.HIGH, f"{subject} listed on {zone}",
                f"Zone {zone} responded {code} for {subject}.",
                f"Investigate the cause and request delisting from {zone}.",
                {"subject": subject, "zone": zone, "code": code},
            ))
    if failures:
        findings.append(Finding(
            check, Severity.INFO, "Some DNSBL queries failed",
            f"{failures} of {len(queries)} queries got no response; the result may be incomplete.",
        ))
    if not any(f.severity is Severity.HIGH for f in findings):
        findings.append(Finding(
            check, Severity.INFO, "Not listed on the DNSBLs queried",
            f"{len(queries) - failures} successful queries "
            f"({len(ips)} mail IP(s) + domain).",
        ))
    return findings
