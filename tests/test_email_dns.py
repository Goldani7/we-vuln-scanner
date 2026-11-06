import dns.exception
import dns.resolver
import pytest

from scanner.checks.email_dns import check_dkim, check_dmarc, check_dnsbl, check_spf
from scanner.finding import Severity


class TXT:
    def __init__(self, text):
        self.strings = [text.encode()]


class MX:
    def __init__(self, host):
        self.exchange = host


class FakeResolver:
    """Resolver falso: `zone` mapeia (nome, tipo) -> lista de rdata; o resto é NXDOMAIN."""

    def __init__(self, zone=None, fail=()):
        self.zone = zone or {}
        self.fail = set(fail)

    def resolve(self, name, rtype):
        if name in self.fail:
            raise dns.resolver.LifetimeTimeout()
        if (name, rtype) not in self.zone:
            raise dns.resolver.NXDOMAIN()
        return self.zone[(name, rtype)]


def _spf(record):
    return FakeResolver({("ex.com", "TXT"): [TXT(record)]})


def _sev(findings, title_part):
    return next(f.severity for f in findings if title_part in f.title)


# SPF
def test_spf_missing_is_high():
    f = check_spf("ex.com", resolver=FakeResolver())
    assert f[0].severity is Severity.HIGH and "ausente" in f[0].title


def test_spf_hard_fail_is_ok():
    f = check_spf("ex.com", resolver=_spf("v=spf1 include:_spf.google.com -all"))
    assert all(x.severity is Severity.INFO for x in f)


@pytest.mark.parametrize("record,title,sev", [
    ("v=spf1 ip4:1.2.3.4 ~all", "~all", Severity.LOW),
    ("v=spf1 ip4:1.2.3.4 ?all", "?all", Severity.MEDIUM),
    ("v=spf1 +all", "+all", Severity.HIGH),
    ("v=spf1 ip4:1.2.3.4", "sem mecanismo", Severity.MEDIUM),
    ("v=spf1 bogus-term -all", "Sintaxe", Severity.MEDIUM),
])
def test_spf_policies(record, title, sev):
    assert _sev(check_spf("ex.com", resolver=_spf(record)), title) is sev


def test_spf_multiple_records_is_high():
    r = FakeResolver({("ex.com", "TXT"): [TXT("v=spf1 -all"), TXT("v=spf1 +all")]})
    assert check_spf("ex.com", resolver=r)[0].severity is Severity.HIGH


def test_spf_too_many_lookups():
    record = "v=spf1 " + " ".join(f"include:s{i}.com" for i in range(11)) + " -all"
    assert _sev(check_spf("ex.com", resolver=_spf(record)), "10 consultas") is Severity.MEDIUM


def test_spf_dns_timeout_does_not_crash():
    f = check_spf("ex.com", resolver=FakeResolver(fail=["ex.com"]))
    assert f[0].severity is Severity.INFO and "falhou" in f[0].title


# DMARC
def _dmarc(record):
    return FakeResolver({("_dmarc.ex.com", "TXT"): [TXT(record)]})


def test_dmarc_missing_is_high():
    assert check_dmarc("ex.com", resolver=FakeResolver())[0].severity is Severity.HIGH


@pytest.mark.parametrize("policy,sev", [
    ("none", Severity.MEDIUM), ("quarantine", Severity.LOW), ("reject", Severity.INFO),
])
def test_dmarc_policy_severity(policy, sev):
    f = check_dmarc("ex.com", resolver=_dmarc(f"v=DMARC1; p={policy}; rua=mailto:d@ex.com"))
    assert _sev(f, "Política DMARC") is sev


def test_dmarc_invalid_policy_and_no_rua():
    f = check_dmarc("ex.com", resolver=_dmarc("v=DMARC1; p=banana"))
    assert _sev(f, "inválida") is Severity.MEDIUM
    assert _sev(f, "rua") is Severity.LOW


def test_dmarc_partial_pct():
    f = check_dmarc("ex.com", resolver=_dmarc("v=DMARC1; p=reject; pct=25; rua=mailto:d@ex.com"))
    assert _sev(f, "25%") is Severity.LOW


# DKIM
def test_dkim_found():
    r = FakeResolver({("google._domainkey.ex.com", "TXT"): [TXT("v=DKIM1; k=rsa; p=MIGfMA0")]})
    f = check_dkim("ex.com", resolver=r)
    assert f[0].severity is Severity.INFO and f[0].metadata["selectors"] == ["google"]


def test_dkim_revoked_key():
    r = FakeResolver({("default._domainkey.ex.com", "TXT"): [TXT("v=DKIM1; p=")]})
    assert _sev(check_dkim("ex.com", resolver=r), "revogada") is Severity.LOW


def test_dkim_wildcard_null_record_is_single_info():
    r = FakeResolver({(f"{s}._domainkey.ex.com", "TXT"): [TXT("v=DKIM1; p=")] for s in ("a", "b")})
    f = check_dkim("ex.com", resolver=r, selectors=["a", "b"])
    assert len(f) == 1 and f[0].severity is Severity.INFO


def test_dkim_not_found_is_inconclusive_low():
    f = check_dkim("ex.com", resolver=FakeResolver())
    assert f[0].severity is Severity.LOW and "não é conclusivo" in f[0].detail


def test_dkim_all_queries_failing_reports_dns_failure():
    names = [f"{s}._domainkey.ex.com" for s in ("a", "b")]
    f = check_dkim("ex.com", resolver=FakeResolver(fail=names), selectors=["a", "b"])
    assert f[0].severity is Severity.INFO and "falhou" in f[0].title


# DNSBL
def _bl_zone(listed=None):
    zone = {("ex.com", "MX"): [MX("mail.ex.com.")], ("mail.ex.com.".rstrip("."), "A"): ["1.2.3.4"]}
    if listed:
        zone[(listed, "A")] = ["127.0.0.2"]
    return FakeResolver(zone)


def test_dnsbl_clean():
    f = check_dnsbl("ex.com", resolver=_bl_zone())
    assert len(f) == 1 and f[0].severity is Severity.INFO


def test_dnsbl_ip_listed():
    f = check_dnsbl("ex.com", resolver=_bl_zone("4.3.2.1.zen.spamhaus.org"))
    hit = next(x for x in f if x.severity is Severity.HIGH)
    assert hit.metadata == {"subject": "1.2.3.4", "zone": "zen.spamhaus.org", "code": "127.0.0.2"}


def test_dnsbl_domain_listed():
    f = check_dnsbl("ex.com", resolver=_bl_zone("ex.com.dbl.spamhaus.org"))
    assert any(x.severity is Severity.HIGH and x.metadata["zone"] == "dbl.spamhaus.org" for x in f)


def test_dnsbl_spamhaus_refusal_is_not_a_listing():
    r = _bl_zone()
    r.zone[("4.3.2.1.zen.spamhaus.org", "A")] = ["127.255.255.254"]
    f = check_dnsbl("ex.com", resolver=r)
    assert not any(x.severity is Severity.HIGH for x in f)
    assert any("falharam" in x.title for x in f)
