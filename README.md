# web-vuln-scanner

Scanner de segurança **passivo e não-invasivo** para aplicações web, feito para fins de portfólio. Realiza apenas requisições `GET`/`HEAD` comuns — sem brute-force, sem exploração ativa e sem wordlists de diretório.

## ⚠️ Aviso ético

Use esta ferramenta **somente em sistemas que você possui ou para os quais tem autorização explícita** para testar. O acesso não autorizado a sistemas é crime: no Brasil, a Lei 12.737/2012 (Lei Carolina Dieckmann) tipifica a invasão de dispositivos informáticos; nos EUA, o Computer Fraud and Abuse Act (CFAA) tem efeito semelhante. O autor não se responsabiliza pelo uso indevido.

## Módulos de verificação

| Módulo | O que verifica |
|---|---|
| `headers` | Presença de CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `cookies` | Flags Secure, HttpOnly e SameSite |
| `tech_detection` | Exposição de `Server`/`X-Powered-By` e CVEs reais da versão detectada (NVD/NIST), com fallback para tabela local |
| `ssl_tls` | Versão do protocolo TLS e validade/expiração do certificado |
| `cors` | Configuração de CORS permissiva ou que reflete origens arbitrárias |
| `exposed_files` | Arquivos sensíveis comuns acessíveis (`/.env`, `/.git/config`, etc.) |

## Instalação

```bash
pip install -r requirements.txt
```

## Uso

```bash
python -m scanner.cli https://exemplo.com
python -m scanner.cli https://exemplo.com --format json --output relatorio.json
python -m scanner.cli https://exemplo.com --checks headers,cookies --no-info
```

Opções: `--checks`, `--format text|json`, `--output`, `--no-info`, `--timeout`.
Código de saída `2` se houver algum finding de severidade alta; caso contrário `0`.

## API web (FastAPI)

```bash
uvicorn api.main:app --reload
curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" \
     -d '{"url":"https://exemplo.com","checks":["headers","cors"]}'
```

| Endpoint | Descrição |
|---|---|
| `POST /scan` | Executa o scan (`{"url": "...", "checks": [...] }`, `checks` opcional) e retorna os findings em JSON |
| `GET /checks` | Lista os módulos com uma descrição educativa de cada um |
| `GET /health` | Health check |

Documentação interativa em `http://localhost:8000/docs`.

### Integração com a NVD

O módulo `tech_detection` consulta a [NVD API](https://nvd.nist.gov/developers) do NIST (gratuita) por tecnologia + versão extraídas dos headers. A variável de ambiente `NVD_API_KEY` é **opcional, mas recomendada**: sem ela a API funciona com limite de requisições menor.

```bash
export NVD_API_KEY="sua-chave"   # chave gratuita: https://nvd.nist.gov/developers/request-an-api-key
```

Os resultados ficam em cache por 7 dias em `~/.cache/web-vuln-scanner/nvd_cache.json` (altere com `NVD_CACHE_PATH`). Se a NVD falhar, o scan continua com a tabela local e um finding INFO avisa da falha. Severidade CVSS: ≥ 9 alto, ≥ 4 médio, abaixo disso baixo.

### ⚠️ Segurança ao expor a API

A API já implementa **rate limiting** (10 scans/minuto por IP, via slowapi) e **validação anti-SSRF** (rejeita localhost, IPs privados/link-local/reservados). Mesmo assim, a validação resolve o DNS só no momento da checagem (DNS rebinding ainda é possível). Expor a API publicamente, além de testes locais, exige também **autenticação** e, idealmente, isolamento de rede. Nunca a exponha sem isso: ela faz requisições a URLs escolhidas pelo usuário.

## Exemplo de saída

```
[ALTO] Header Content-Security-Policy ausente
    A resposta não contém o header Content-Security-Policy.
    Recomendação: Defina uma CSP restritiva para mitigar XSS e injeção de conteúdo.
[MÉDIO] Header Strict-Transport-Security ausente
    ...
[INFO] Protocolo TLS: TLSv1.3

Resumo: ALTO=1, MÉDIO=1, BAIXO=2, INFO=5
```

## Estrutura

```
web-vuln-scanner/
  scanner/
    finding.py   core.py   report.py   cli.py   nvd.py
    checks/      headers, ssl_tls, cookies, cors, exposed_files, tech_detection
  api/
    main.py   validation.py
  tests/
    test_headers.py   test_api.py   test_tech_detection.py
```

Testes: `pip install -r requirements-dev.txt && pytest tests/ -q`

## Roadmap

- [ ] Enumeração de subdomínios via crt.sh
- [x] Integração real com a NVD para checar CVEs
- [x] API web (FastAPI)
- [ ] Relatório em PDF/HTML
- [ ] Modo assíncrono

## Disclaimer

Esta ferramenta **não substitui um pentest profissional**. Ela detecta apenas problemas superficiais de configuração.

## Licença

MIT — veja [LICENSE](LICENSE).
