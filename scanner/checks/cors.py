"""CORS permissivo.

Vulnerabilidade: se o servidor reflete qualquer Origin (ou usa * com credenciais), um site
malicioso consegue ler respostas autenticadas da vítima.
Exemplo: evil.com faz fetch(api, {credentials:"include"}) e lê os dados privados do usuário logado.
Ref.: OWASP WSTG-CLNT-07 (Testing CORS); CWE-942.
"""
import requests

from ..finding import Finding, Severity

CHECK = "cors"
TEST_ORIGIN = "https://evil-example-probe.test"


def check_cors(url: str, timeout: int = 8) -> list:
    try:
        r = requests.get(url, headers={"Origin": TEST_ORIGIN}, timeout=timeout)
    except requests.RequestException as e:
        return [Finding(CHECK, Severity.INFO, "Não foi possível testar CORS", str(e))]

    acao = r.headers.get("Access-Control-Allow-Origin")
    creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    meta = {"allow_origin": acao, "allow_credentials": creds}

    if acao == "*" and creds:
        return [Finding(
            CHECK, Severity.HIGH, "CORS permite qualquer origem com credenciais",
            "Access-Control-Allow-Origin: * combinado com Allow-Credentials: true.",
            "Restrinja as origens a uma lista explícita de domínios confiáveis.", meta,
        )]
    if acao == TEST_ORIGIN:
        return [Finding(
            CHECK, Severity.HIGH, "CORS reflete origem arbitrária",
            f"O servidor refletiu a origem de teste {TEST_ORIGIN}.",
            "Valide a origem contra uma allowlist em vez de refleti-la.", meta,
        )]
    if acao == "*":
        return [Finding(
            CHECK, Severity.LOW, "CORS permite qualquer origem",
            "Access-Control-Allow-Origin: * (sem credenciais).",
            "Restrinja as origens se a API não for pública.", meta,
        )]
    return [Finding(CHECK, Severity.INFO, "CORS sem configuração permissiva", metadata=meta)]
