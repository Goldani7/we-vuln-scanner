from typing import List, Optional

from fastapi import FastAPI, Request
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from scanner.core import ALL_CHECKS, scan

from .validation import validate_public_url

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="web-vuln-scanner API", version="0.2.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

CHECK_DESCRIPTIONS = {
    "headers": "Verifica headers de segurança (CSP, HSTS, X-Frame-Options...). Eles instruem o "
               "navegador a bloquear XSS, clickjacking e downgrade para HTTP.",
    "cookies": "Verifica as flags Secure, HttpOnly e SameSite dos cookies. Sem elas, cookies de "
               "sessão podem ser roubados via XSS, rede insegura ou CSRF.",
    "tech_detection": "Detecta software/versão expostos em Server/X-Powered-By e consulta CVEs "
                      "conhecidas na NVD. Versões antigas têm exploits públicos.",
    "ssl_tls": "Verifica versão do TLS e validade do certificado. Protocolos antigos e "
               "certificados expirados permitem interceptação e quebram a confiança.",
    "cors": "Testa se o CORS aceita origens arbitrárias. Uma política permissiva deixa sites "
            "maliciosos ler respostas autenticadas do usuário.",
    "exposed_files": "Procura arquivos sensíveis comuns (.env, .git, backups) e valida o conteúdo "
                     "para evitar falsos positivos. Eles costumam vazar credenciais e código-fonte.",
    "misconfig": "Verifica redirecionamento HTTP→HTTPS, método TRACE, listagem de diretório e "
                 "páginas de erro com stack trace, que vazam informação sobre o servidor.",
}


class ScanRequest(BaseModel):
    url: str
    checks: Optional[List[str]] = None

    @field_validator("url")
    @classmethod
    def _check_url(cls, v):
        return validate_public_url(v)

    @field_validator("checks")
    @classmethod
    def _check_names(cls, v):
        if v is not None:
            invalid = [c for c in v if c not in ALL_CHECKS]
            if invalid:
                raise ValueError(f"Checks inválidos: {', '.join(invalid)}")
        return v


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/checks")
def list_checks():
    return [{"name": n, "description": CHECK_DESCRIPTIONS[n]} for n in ALL_CHECKS]


@app.post("/scan")
@limiter.limit("10/minute")
def run_scan(request: Request, body: ScanRequest):
    findings = scan(body.url, checks=body.checks)
    return [f.to_dict() for f in findings]
