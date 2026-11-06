"""Plugin de exemplo: respostas que definem cookies devem impedir cache compartilhado.

Vulnerabilidade: se uma resposta com Set-Cookie (ex.: sessão) puder ser armazenada por um proxy ou CDN,
outro usuário pode receber a sessão da vítima.
Ref.: OWASP WSTG-ATHN-06 (Browser Cache Weaknesses); CWE-524.
"""
from scanner.finding import Finding, Severity
from scanner.registry import CheckSpec


def check_cache_control(response) -> list:
    """Assinatura "response": recebe a resposta httpx da página inicial e devolve uma lista de Finding."""
    if not response.headers.get_list("set-cookie"):
        return [Finding("cache_control", Severity.INFO, "Resposta sem cookies: Cache-Control não aplicável",
                        rule_id="cache_control.na")]
    cc = response.headers.get("cache-control", "").lower()
    if any(token in cc for token in ("no-store", "private")):
        return [Finding("cache_control", Severity.INFO, "Resposta com cookies impede cache compartilhado",
                        evidence=f"Cache-Control: {cc}", rule_id="cache_control.ok")]
    return [Finding(
        "cache_control", Severity.MEDIUM, "Resposta com Set-Cookie pode ser armazenada em cache compartilhado",
        "Sem 'no-store' ou 'private', um proxy/CDN pode servir a sessão de um usuário a outro.",
        "Envie 'Cache-Control: no-store' (ou 'private') nas respostas que definem cookies.",
        evidence=f"Cache-Control: {cc or 'ausente'}", cwe="CWE-524", confidence="medium",
        rule_id="cache_control.shared-cache")]


SPEC = CheckSpec(
    name="cache_control", kind="response", func=check_cache_control, category="web",
    description="Respostas com cookies devem enviar Cache-Control: no-store/private.",
)
