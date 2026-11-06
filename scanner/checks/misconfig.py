"""Misconfigurações comuns de servidor.

Vulnerabilidades cobertas (todas por requisições comuns, sem payloads de ataque):
- HTTP sem redirecionamento para HTTPS (credenciais/sessões trafegam em claro);
- método TRACE habilitado (Cross-Site Tracing); métodos de escrita anunciados em Allow;
- listagem de diretório (vaza arquivos e backups);
- páginas de erro com stack trace/debug (vaza caminhos, versões e consultas SQL);
- ausência de security.txt (RFC 9116), útil para disclosure responsável.
Exemplo: /uploads/ com "Index of /uploads" lista dump.sql; um erro 500 com traceback revela o
caminho do código e a versão do framework, acelerando a exploração.
Ref.: OWASP A05:2021; CWE-548 (directory listing), CWE-209 (error message info leak), CWE-693.
"""
import asyncio
import re
import uuid
from urllib.parse import urljoin, urlparse

from ..finding import Finding, Severity
from ..http import RequestFailed

CHECK = "misconfig"
OWASP_A05 = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"

LISTING_PATHS = ["/", "/uploads/", "/backup/", "/backups/", "/files/", "/images/",
                 "/static/", "/assets/", "/logs/", "/tmp/"]
_LISTING = re.compile(
    r"<title>Index of /|<h1>Index of /|Directory listing for /|\[To Parent Directory\]|"
    r"<title>Directory Listing For", re.I)
_SENSITIVE_EXT = re.compile(r"\.(sql|bak|zip|tar|gz|env|log|old|key|pem|conf|ini)\b", re.I)

ERROR_SIGNATURES = [
    (r"Traceback \(most recent call last\)", "traceback Python"),
    (r"Whitelabel Error Page", "página de erro padrão do Spring Boot"),
    (r"You're seeing this error because you have <code>DEBUG = True", "Django com DEBUG=True"),
    (r"Server Error in '/[^']*' Application", "erro detalhado do ASP.NET"),
    (r"\bat [\w.$]+\([\w]+\.java:\d+\)", "stack trace Java"),
    (r"<b>(Warning|Fatal error|Notice)</b>:.{0,200} on line <b>\d+</b>", "erro PHP com caminho do arquivo"),
    (r"Whoops! There was an error|Symfony Exception|facade/ignition", "página de debug (Laravel/Symfony)"),
    (r"You have an error in your SQL syntax|ORA-\d{5}|SQLSTATE\[\w+\]|PG::\w*Error", "erro de banco de dados"),
]


async def _get(ctx, path_or_url, method="GET", **kw):
    url = path_or_url if "://" in path_or_url else urljoin(ctx.url, path_or_url)
    try:
        return await ctx.client.request(method, url, **kw)
    except RequestFailed:
        return None


async def _https_redirect(ctx) -> list:
    p = urlparse(ctx.url)
    if p.scheme != "https" or p.port not in (None, 443):
        return []
    url = f"http://{p.hostname}/"
    r = await _get(ctx, url)
    if r is None:
        return []  # porta 80 fechada: nada a reportar
    location = r.headers.get("location", "")
    if 300 <= r.status_code < 400 and location.lower().startswith("https://"):
        return [Finding(CHECK, Severity.INFO, "HTTP redireciona para HTTPS",
                        evidence=f"GET {url} → {r.status_code} Location: {location}",
                        rule_id="misconfig.https-redirect-ok")]
    if r.status_code < 400:
        return [Finding(
            CHECK, Severity.MEDIUM, "HTTP não redireciona para HTTPS",
            "O site responde em texto claro na porta 80 sem redirecionar, permitindo que a primeira "
            "requisição (e cookies sem Secure) seja interceptada.",
            "Redirecione todo o tráfego HTTP para HTTPS (301) e habilite HSTS.",
            evidence=f"GET {url} → HTTP {r.status_code}" + (f" Location: {location}" if location else ""),
            cwe="CWE-319", references=[OWASP_A05], confidence="high", rule_id="misconfig.no-https-redirect")]
    return []


async def _http_methods(ctx) -> list:
    findings = []
    opts = await _get(ctx, ctx.url, "OPTIONS", follow_redirects=True)
    allow = {m.strip().upper() for m in (opts.headers.get("allow", "") if opts else "").split(",") if m.strip()}

    trace = await _get(ctx, ctx.url, "TRACE", headers={"X-WVS-Probe": "trace-echo"})
    if trace is not None and trace.status_code == 200 and "trace-echo" in trace.text.lower():
        findings.append(Finding(
            CHECK, Severity.MEDIUM, "Método HTTP TRACE habilitado",
            "O servidor ecoa a requisição completa (Cross-Site Tracing), podendo expor headers "
            "como cookies/credenciais de proxies em cenários de XSS.",
            "Desabilite TRACE (Apache: TraceEnable off; nginx não o suporta por padrão).",
            evidence="TRACE retornou 200 refletindo o header X-WVS-Probe",
            cwe="CWE-693", references=[OWASP_A05], confidence="high", rule_id="misconfig.trace"))
    risky = sorted(allow & {"PUT", "DELETE", "CONNECT"})
    if risky:
        findings.append(Finding(
            CHECK, Severity.LOW, f"Métodos potencialmente perigosos anunciados: {', '.join(risky)}",
            "O header Allow lista métodos de escrita. Isto só indica configuração: o scanner não "
            "tenta modificar nada, então valide manualmente.",
            "Restrinja os métodos permitidos ao mínimo necessário por rota.",
            evidence=f"OPTIONS → Allow: {', '.join(sorted(allow))}",
            cwe="CWE-749", references=[OWASP_A05], confidence="low", rule_id="misconfig.methods"))
    return findings


async def _directory_listing(ctx) -> list:
    responses = await asyncio.gather(*[_get(ctx, p) for p in LISTING_PATHS])
    findings = []
    for path, r in zip(LISTING_PATHS, responses):
        if r is None or r.status_code != 200 or not _LISTING.search(r.text[:20000]):
            continue
        names = re.findall(r'href="([^"?#]+)"', r.text)
        names = [n for n in names if not n.startswith(("/", "?", "http")) and n != "../"]
        sensitive = [n for n in names if _SENSITIVE_EXT.search(n)]
        findings.append(Finding(
            CHECK, Severity.HIGH if sensitive else Severity.MEDIUM,
            f"Listagem de diretório habilitada em {path}",
            "O servidor lista o conteúdo do diretório, facilitando a descoberta de arquivos que "
            "não deveriam ser públicos." + (f" Há arquivos sensíveis: {', '.join(sensitive[:5])}." if sensitive else ""),
            "Desabilite a listagem (Apache: Options -Indexes; nginx: autoindex off) e remova "
            "arquivos que não devem ser públicos.",
            {"path": path, "entries": names[:50]},
            evidence="Entradas: " + (", ".join(names[:8]) or "(nenhuma extraída)"),
            cwe="CWE-548", references=[OWASP_A05], confidence="high", rule_id="misconfig.dir-listing"))
    return findings


async def _error_disclosure(ctx) -> list:
    bodies = []
    try:
        bodies.append(("página inicial", (await ctx.index()).text[:50000]))
    except RequestFailed:
        pass
    miss = await _get(ctx, f"/{uuid.uuid4().hex}")
    if miss is not None:
        bodies.append(("resposta a um caminho inexistente", miss.text[:50000]))
    findings, seen = [], set()
    for where, text in bodies:
        for pattern, label in ERROR_SIGNATURES:
            m = re.search(pattern, text, re.I | re.S)
            if m and label not in seen:
                seen.add(label)
                snippet = re.sub(r"\s+", " ", text[max(0, m.start() - 40): m.end() + 80]).strip()
                findings.append(Finding(
                    CHECK, Severity.MEDIUM, f"Vazamento de informação em erro: {label}",
                    f"A {where} contém detalhes internos ({label}), úteis para o atacante.",
                    "Desative o modo debug em produção e use páginas de erro genéricas; registre "
                    "detalhes apenas em logs internos.",
                    evidence=snippet[:200], cwe="CWE-209", references=[OWASP_A05],
                    confidence="high", rule_id="misconfig.error-disclosure"))
    return findings


async def _security_txt(ctx) -> list:
    r = await _get(ctx, "/.well-known/security.txt")
    if r is not None and r.status_code == 200 and "contact:" in r.text.lower():
        return [Finding(CHECK, Severity.INFO, "security.txt presente",
                        evidence=r.text[:200], rule_id="misconfig.security-txt-ok")]
    return [Finding(CHECK, Severity.INFO, "security.txt ausente",
                    "Sem /.well-known/security.txt, pesquisadores não sabem como reportar falhas.",
                    "Publique um security.txt (RFC 9116) com Contact e Expires.",
                    rule_id="misconfig.security-txt-missing", confidence="high")]


async def check_misconfig(ctx) -> list:
    results = await asyncio.gather(
        _https_redirect(ctx), _http_methods(ctx), _directory_listing(ctx),
        _error_disclosure(ctx), _security_txt(ctx))
    return [f for group in results for f in group]
