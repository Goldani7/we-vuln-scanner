"""Enumeração PASSIVA de subdomínios via Certificate Transparency (crt.sh).

Por quê: a superfície de ataque real de uma organização raramente é o domínio principal; staging,
admin, VPN e serviços esquecidos aparecem em certificados públicos. A consulta vai à crt.sh (não ao
alvo), então não há brute-force nem tráfego contra o domínio além de resolver os nomes via DNS.
Exemplo: "staging-api.empresa.com" aparece num certificado e roda uma versão antiga sem autenticação.
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
    """Nomes únicos sob `domain` extraídos do JSON da crt.sh (wildcards normalizados)."""
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
        return [Finding(CHECK, Severity.INFO, "Enumeração de subdomínios ignorada",
                        f"'{domain}' é um IP ou nome local, sem Certificate Transparency.",
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
        return [Finding(CHECK, Severity.INFO, "crt.sh indisponível; subdomínios não enumerados",
                        f"Não foi possível consultar a crt.sh ({reason}). O serviço é conhecido por "
                        "instabilidade.", "Execute novamente mais tarde.", rule_id="subdomains.unavailable")]

    names = parse_crtsh(payload, domain)
    if not names:
        return [Finding(CHECK, Severity.INFO, "Nenhum subdomínio em Certificate Transparency",
                        f"A crt.sh não retornou certificados para subdomínios de {domain}.",
                        rule_id="subdomains.none")]

    resolved = await resolve_many(names[:MAX_RESOLVE])
    live = {n: ips for n, ips in resolved.items() if ips}
    capped = f" (resolução limitada aos primeiros {MAX_RESOLVE})" if len(names) > MAX_RESOLVE else ""
    evidence = "\n".join(f"{n} → {', '.join(live[n])}" if n in live else f"{n} (não resolve)"
                         for n in names[:40])
    if len(names) > 40:
        evidence += f"\n… (+{len(names) - 40})"
    findings = [Finding(
        CHECK, Severity.INFO, f"{len(names)} subdomínios descobertos via Certificate Transparency",
        f"{len(live)} resolvem em DNS{capped}. Cada um é superfície de ataque a revisar.",
        "Inventarie estes hosts, desative os que não são mais usados e revise o escopo do pentest.",
        {"subdomains": [{"name": n, "ips": resolved.get(n, [])} for n in names]},
        evidence=evidence, cwe="CWE-200", references=["https://crt.sh/"], confidence="high",
        rule_id="subdomains.discovered")]

    sensitive = [n for n in live if SENSITIVE_NAME.search(n[: -len(domain) - 1])]
    if sensitive:
        findings.append(Finding(
            CHECK, Severity.LOW, f"{len(sensitive)} subdomínios de ambiente interno/não produtivo expostos",
            "Nomes como dev/staging/admin/vpn costumam ter menos hardening e dados reais.",
            "Restrinja por VPN/IP, exija autenticação e remova DNS/certificados de ambientes desativados.",
            {"subdomains": sensitive}, evidence="\n".join(f"{n} → {', '.join(live[n])}" for n in sensitive[:20]),
            cwe="CWE-668", confidence="medium", rule_id="subdomains.sensitive-names"))

    private = {n: [ip for ip in ips if ipaddress.ip_address(ip).is_private]
               for n, ips in live.items()}
    private = {n: ips for n, ips in private.items() if ips}
    if private:
        findings.append(Finding(
            CHECK, Severity.LOW, f"{len(private)} subdomínios públicos apontam para IPs privados",
            "O DNS público revela a topologia interna (RFC 1918) e pode ser usado em ataques de DNS rebinding.",
            "Mova registros internos para DNS interno (split-horizon).",
            {"subdomains": private}, evidence="\n".join(f"{n} → {', '.join(ips)}" for n, ips in list(private.items())[:20]),
            cwe="CWE-200", confidence="high", rule_id="subdomains.private-ip"))
    return findings
