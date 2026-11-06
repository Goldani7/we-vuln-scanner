"""Sondagem ATIVA de WAF (check ativo: só roda com --allow-active e dentro do --scope).

Método: além da baseline (GET normal, já buscada pelo scan), envia UMA requisição extra com um
parâmetro de consulta contendo um padrão genérico e bem conhecido de teste de WAF (estilo de
path traversal), usado por ferramentas de fingerprinting como o wafw00f. Não é um payload
funcional: é só uma string "suspeita" para ver se o WAF reage, e vai num parâmetro (`wvs_probe`)
que a aplicação não deveria processar. Nenhum dado é alterado, nenhuma exploração é tentada.
Por quê: muitos WAFs só se revelam ao bloquear algo. A detecção passiva (`waf.py`) não pega esses
casos; esta sondagem confirma a presença ativa e, quando bloqueia, tenta identificar o fornecedor
pela mesma tabela de assinaturas do módulo passivo.
Ref.: técnica usada pelo wafw00f; OWASP WSTG-INFO-02.
"""
from urllib.parse import urlsplit, urlunsplit

from ..finding import Finding, Severity
from ..http import RequestFailed
from .waf import BLOCK_STATUSES, detect

CHECK = "waf_active"
PROBE_PARAM = "wvs_probe"
PROBE_VALUE = "../../../../etc/passwd"
REFERENCE = "https://github.com/EnableSecurity/wafw00f"


def _probe_url(url: str) -> str:
    parts = urlsplit(url)
    query = f"{parts.query}&{PROBE_PARAM}={PROBE_VALUE}" if parts.query else f"{PROBE_PARAM}={PROBE_VALUE}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _vendor_names(response) -> list:
    return [sig.name for sig, _hits in detect(response)]


async def check_waf_active(ctx) -> list:
    try:
        baseline = await ctx.index()
    except RequestFailed as e:
        return [Finding(CHECK, Severity.INFO, "Sondagem ativa de WAF não executada: baseline indisponível",
                        e.describe(), rule_id="waf_active.no-baseline")]

    if baseline.status_code in BLOCK_STATUSES:
        return [Finding(
            CHECK, Severity.INFO, "Sondagem ativa de WAF não é conclusiva",
            f"A própria resposta de baseline já veio bloqueada (HTTP {baseline.status_code}); "
            "não é possível diferenciar o bloqueio normal do provocado pela sondagem.",
            rule_id="waf_active.inconclusive")]

    try:
        probe = await ctx.client.request("GET", _probe_url(ctx.url), follow_redirects=True)
    except RequestFailed as e:
        return [Finding(CHECK, Severity.INFO, "Sondagem ativa de WAF falhou", e.describe(),
                        rule_id="waf_active.error")]

    evidence = (f"Baseline: GET {ctx.url} → HTTP {baseline.status_code}\n"
               f"Sonda: GET {ctx.url}?{PROBE_PARAM}=<path traversal> → HTTP {probe.status_code}")
    if probe.status_code not in BLOCK_STATUSES:
        return [Finding(
            CHECK, Severity.INFO, "Sondagem ativa não observou bloqueio", evidence,
            "Isto não prova a ausência de WAF: ele pode não reagir a este padrão específico, ou "
            "atuar apenas sobre outras classes de ataque.",
            rule_id="waf_active.no-block", confidence="low")]

    vendors = _vendor_names(probe)
    detail = ("O servidor bloqueou uma requisição com um padrão suspeito (path traversal) mas não "
             "a requisição normal, confirmando um WAF ativo." +
             (f" Fornecedor identificado pela resposta de bloqueio: {', '.join(vendors)}." if vendors else ""))
    return [Finding(
        CHECK, Severity.INFO, f"WAF ativo confirmado{' (' + vendors[0] + ')' if vendors else ''}",
        detail, "Nenhuma ação necessária: isto é uma confirmação, não uma vulnerabilidade. Resultados "
        "de outros checks podem estar sendo filtrados pelo WAF.",
        {"vendors": vendors, "probe_status": probe.status_code, "baseline_status": baseline.status_code},
        evidence=evidence, references=[REFERENCE], confidence="high", rule_id="waf_active.confirmed")]
