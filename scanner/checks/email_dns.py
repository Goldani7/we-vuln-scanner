"""Segurança de e-mail e reputação do domínio: SPF, DKIM, DMARC e DNSBL.

Vulnerabilidade: sem SPF/DKIM/DMARC qualquer servidor pode enviar e-mails em nome do domínio,
facilitando phishing e fraude (BEC).
Exemplo: sem DMARC com p=reject, um atacante envia "ceo@dominio.com" pedindo uma transferência e
o servidor do destinatário não tem instrução para descartar a mensagem forjada.
Ref.: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC); MITRE ATT&CK T1566 (Phishing).
Nota: só consultas DNS públicas; nenhum e-mail é enviado.
"""
import ipaddress
import logging
import re

import dns.exception
import dns.resolver

from ..finding import Finding, Severity

log = logging.getLogger(__name__)

# Seletores DKIM comuns. DKIM não permite listar seletores: só dá para testar nomes conhecidos,
# então a ausência de resultado nunca prova que o DKIM não existe.
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
    "s1", "s2", "smtp", "mandrill", "mxvault", "zoho", "protonmail",
]

# Zonas DNSBL consultadas. Todas aceitam consultas gratuitas de baixo volume.
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
    """Consulta DNS que devolve [] se o nome não existe ou não tem o registro.

    Timeouts e falhas de resolução propagam como dns.exception.DNSException para o chamador
    decidir como reportar (ausência de registro é diferente de DNS indisponível).
    """
    try:
        return list(resolver.resolve(name, rtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []


def _txt_records(resolver, name: str) -> list:
    """Registros TXT como strings (os pedaços de 255 bytes de cada registro são concatenados)."""
    return [b"".join(r.strings).decode("utf-8", "replace") for r in _query(resolver, name, "TXT")]


def _dns_failure(check: str, name: str, err: Exception) -> Finding:
    return Finding(
        check, Severity.INFO, f"Consulta DNS falhou para {name}",
        f"{type(err).__name__}: {err}",
        "Verifique a conectividade/resolução DNS e execute novamente.",
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
            check, Severity.HIGH, "Registro SPF ausente",
            f"{domain} não publica um TXT começando com 'v=spf1'.",
            "Publique um SPF listando os servidores autorizados e terminando em -all "
            "(ex.: 'v=spf1 include:_spf.seu-provedor.com -all').",
        )]
    if len(records) > 1:
        return [Finding(
            check, Severity.HIGH, "Múltiplos registros SPF",
            f"{len(records)} registros SPF encontrados; a RFC 7208 exige exatamente um "
            "(o resultado é permerror e o SPF é ignorado).",
            "Una os registros em um só.", {"records": records},
        )]

    record = records[0]
    terms = record.split()[1:]
    findings = [Finding(check, Severity.INFO, "Registro SPF presente", record, metadata={"record": record})]

    invalid = [t for t in terms if not (_SPF_MECHANISM.match(t) or _SPF_MODIFIER.match(t))]
    if invalid:
        findings.append(Finding(
            check, Severity.MEDIUM, "Sintaxe SPF suspeita",
            f"Termos não reconhecidos: {', '.join(invalid)}.",
            "Corrija a sintaxe; receptores podem tratar o registro inteiro como erro.",
            {"terms": invalid},
        ))

    all_term = next((t for t in terms if t.lstrip("+-~?").lower() == "all"), None)
    policy = {
        "-all": (Severity.INFO, "SPF com -all (hard fail)", ""),
        "~all": (Severity.LOW, "SPF com ~all (soft fail)",
                 "Migre para -all quando todos os remetentes legítimos estiverem listados."),
        "?all": (Severity.MEDIUM, "SPF com ?all (neutro)",
                 "?all não protege contra falsificação; use -all ou ~all."),
        "+all": (Severity.HIGH, "SPF com +all (autoriza qualquer servidor)",
                 "Substitua +all por -all: do jeito atual qualquer um pode falsificar o domínio."),
        "all": (Severity.HIGH, "SPF com 'all' (equivale a +all)",
                "Substitua por -all."),
    }
    if all_term is None and not any(t.lower().startswith("redirect=") for t in terms):
        findings.append(Finding(
            check, Severity.MEDIUM, "SPF sem mecanismo 'all' final",
            "Sem 'all' (ou redirect=), remetentes não listados recebem resultado neutro.",
            "Termine o registro com -all.",
        ))
    elif all_term is not None:
        sev, title, rec = policy[all_term.lower()]
        findings.append(Finding(check, sev, title, f"Terminador do registro: {all_term}", rec))

    lookups = _spf_lookup_count(terms)
    if lookups > 10:
        findings.append(Finding(
            check, Severity.MEDIUM, "SPF excede o limite de 10 consultas DNS",
            f"Estimativa de {lookups} mecanismos que geram consultas (limite da RFC 7208: 10).",
            "Reduza includes ou use 'flattening'; acima do limite o SPF falha com permerror.",
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
            check, Severity.INFO, f"DKIM publicado ({len(found)} seletor(es))",
            f"Seletores encontrados: {', '.join(found)}.", metadata={"selectors": found},
        ))
    tested = len(selectors or DKIM_SELECTORS)
    if revoked and not found and len(revoked) == tested:
        # Wildcard '*._domainkey' com p= vazio: prática recomendada para domínios que não enviam e-mail.
        return [Finding(
            check, Severity.INFO, "DKIM explicitamente desabilitado (chaves vazias)",
            "Todos os seletores testados retornam chave vazia (p=), típico de wildcard em domínio "
            "que não envia e-mail.", metadata={"selectors": revoked},
        )]
    if revoked:
        findings.append(Finding(
            check, Severity.LOW, "Chave DKIM revogada (p= vazio)",
            f"Seletores com chave vazia: {', '.join(revoked)}.",
            "Remova seletores antigos ou publique uma chave válida se ainda forem usados.",
            {"selectors": revoked},
        ))
    if not found and not revoked:
        if errors == len(selectors or DKIM_SELECTORS):
            return [_dns_failure(check, domain, RuntimeError("todas as consultas falharam"))]
        findings.append(Finding(
            check, Severity.LOW, "Nenhum seletor DKIM padrão encontrado",
            f"Testados {len(selectors or DKIM_SELECTORS)} seletores comuns. Isto não é conclusivo: "
            "o domínio pode usar um seletor personalizado.",
            "Confirme com o provedor de e-mail e assine as mensagens com DKIM.",
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
            check, Severity.HIGH, "Registro DMARC ausente",
            f"Nenhum TXT 'v=DMARC1' em {name}.",
            "Publique DMARC começando em p=none com rua= para coletar relatórios e evolua "
            "para quarantine e depois reject.",
        )]

    record = records[0]
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p", "").lower()
    findings = [Finding(check, Severity.INFO, "Registro DMARC presente", record,
                        metadata={"record": record, "policy": policy})]

    table = {
        "none": (Severity.MEDIUM, "Política DMARC p=none (apenas monitoramento)",
                 "p=none não bloqueia e-mails falsificados; evolua para quarantine/reject."),
        "quarantine": (Severity.LOW, "Política DMARC p=quarantine",
                       "Considere p=reject quando os relatórios mostrarem que só há tráfego legítimo."),
        "reject": (Severity.INFO, "Política DMARC p=reject", ""),
    }
    if policy in table:
        sev, title, rec = table[policy]
        findings.append(Finding(check, sev, title, f"p={policy}", rec))
    else:
        findings.append(Finding(
            check, Severity.MEDIUM, "Política DMARC inválida ou ausente",
            f"Tag p= ausente ou com valor desconhecido ({policy!r}); receptores ignoram o registro.",
            "Defina p=none, quarantine ou reject.",
        ))

    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject"):
        findings.append(Finding(
            check, Severity.LOW, f"DMARC aplicado a apenas {pct}% das mensagens",
            f"pct={pct}", "Eleve para pct=100 depois da fase de testes.",
        ))
    if "rua" not in tags:
        findings.append(Finding(
            check, Severity.LOW, "DMARC sem endereço de relatórios (rua)",
            "Sem rua= você não recebe relatórios agregados sobre quem envia e-mails pelo domínio.",
            "Adicione rua=mailto:dmarc@seu-dominio.",
        ))
    return findings


# ------------------------------------------------------------------------- DNSBL

def _mail_ips(resolver, domain: str) -> list:
    """IPv4 dos servidores de e-mail (MX) do domínio; sem MX, usa o A do próprio domínio."""
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
    """Código de retorno 127.x.x.x se listado; None se não listado.

    Levanta DNSException em falha de consulta. Respostas 127.255.255.x (Spamhaus) indicam
    erro/resolver bloqueado e não listagem, então são tratadas como falha.
    """
    answers = _query(resolver, query_name, "A")
    if not answers:
        return None
    code = str(answers[0])
    if code.startswith("127.255.255."):
        raise dns.exception.DNSException(f"DNSBL recusou a consulta ({code}); resolver público bloqueado?")
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
                check, Severity.HIGH, f"{subject} listado em {zone}",
                f"A zona {zone} respondeu {code} para {subject}.",
                f"Investigue a causa e solicite a remoção (delisting) em {zone}.",
                {"subject": subject, "zone": zone, "code": code},
            ))
    if failures:
        findings.append(Finding(
            check, Severity.INFO, "Algumas consultas DNSBL falharam",
            f"{failures} de {len(queries)} consultas sem resposta; o resultado pode estar incompleto.",
        ))
    if not any(f.severity is Severity.HIGH for f in findings):
        findings.append(Finding(
            check, Severity.INFO, "Não listado nas DNSBLs consultadas",
            f"{len(queries) - failures} consultas bem-sucedidas "
            f"({len(ips)} IP(s) de e-mail + domínio).",
        ))
    return findings
