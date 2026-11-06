"""CORS permissivo.

Vulnerabilidade: se o servidor reflete qualquer Origin com credenciais permitidas, um site
malicioso consegue ler respostas autenticadas da vítima.
Exemplo: evil.com faz fetch(api, {credentials:"include"}) e lê os dados privados do usuário logado.
Ref.: OWASP WSTG-CLNT-07 (Testing CORS); CWE-942.
"""
from ..finding import Finding, Severity
from ..http import RequestFailed

CHECK = "cors"
TEST_ORIGIN = "https://evil-example-probe.test"
REFERENCE = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"
FIX = "Valide a origem contra uma allowlist explícita em vez de refleti-la, e só envie Allow-Credentials para origens confiáveis."


def _finding(severity, title, detail, evidence, meta, remediation=FIX, confidence="high", rule="cors.misconfig"):
    return Finding(CHECK, severity, title, detail, remediation, meta, evidence=evidence,
                   cwe="CWE-942", references=[REFERENCE], confidence=confidence, rule_id=rule)


async def check_cors(ctx) -> list:
    findings = []
    for origin in (TEST_ORIGIN, "null"):
        try:
            r = await ctx.client.request("GET", ctx.url, headers={"Origin": origin}, follow_redirects=True)
        except RequestFailed as e:
            return [Finding(CHECK, Severity.INFO, "Não foi possível testar CORS", e.describe(),
                            rule_id="cors.unreachable")]
        acao = r.headers.get("Access-Control-Allow-Origin")
        creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        meta = {"origin_sent": origin, "allow_origin": acao, "allow_credentials": creds}
        evidence = f"Origin: {origin} → Access-Control-Allow-Origin: {acao}; Allow-Credentials: {creds}"
        reflected = acao == origin

        if reflected and creds:
            findings.append(_finding(
                Severity.HIGH, "CORS reflete origem arbitrária com credenciais" if origin != "null"
                else "CORS aceita Origin 'null' com credenciais",
                "Qualquer site (ou iframe sandbox, no caso de 'null') consegue ler respostas "
                "autenticadas da vítima.", evidence, meta))
        elif reflected and origin != "null":
            findings.append(_finding(
                Severity.LOW, "CORS reflete origem arbitrária (sem credenciais)",
                "Sem credenciais só dados públicos são legíveis, mas a política é frouxa.",
                evidence, meta))
        elif acao == "*" and creds and origin != "null":
            findings.append(_finding(
                Severity.MEDIUM, "CORS combina * com Allow-Credentials",
                "Navegadores rejeitam esta combinação, mas ela indica configuração incorreta.",
                evidence, meta))
        elif acao == "*" and origin != "null":
            findings.append(_finding(
                Severity.LOW, "CORS permite qualquer origem",
                "Access-Control-Allow-Origin: * (sem credenciais).", evidence, meta,
                "Restrinja as origens se a API não for pública.", rule="cors.wildcard"))
    return findings or [Finding(CHECK, Severity.INFO, "CORS sem configuração permissiva",
                                rule_id="cors.ok")]
