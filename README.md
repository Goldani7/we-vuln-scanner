# web-vuln-scanner

Scanner de segurança **passivo e não-invasivo** para aplicações web e para a saúde de e-mail/DNS de um domínio, feito para fins de portfólio. Realiza apenas requisições `GET`/`HEAD` comuns — sem brute-force, sem exploração ativa e sem wordlists de diretório.

## ⚠️ Aviso ético

Use esta ferramenta **somente em sistemas que você possui ou para os quais tem autorização explícita** para testar. O acesso não autorizado a sistemas é crime: no Brasil, a Lei 12.737/2012 (Lei Carolina Dieckmann) tipifica a invasão de dispositivos informáticos; nos EUA, o Computer Fraud and Abuse Act (CFAA) tem efeito semelhante. O autor não se responsabiliza pelo uso indevido.

## Módulos de verificação

| Módulo | O que verifica |
|---|---|
| `headers` | Avalia o **valor**, não só a presença: CSP com `unsafe-inline`/curingas, HSTS com `max-age` curto ou sem `includeSubDomains`, `X-Frame-Options` inválido (considera `frame-ancestors`), `nosniff`, `Referrer-Policy` insegura, COOP/CORP, vazamento de versão (`X-AspNet-Version`) |
| `cookies` | Flags Secure, HttpOnly e SameSite, priorizando cookies com nome de sessão/autenticação. O valor do cookie nunca vai para o relatório |
| `tech_detection` | Exposição de `Server`/`X-Powered-By` e CVEs da versão detectada (NVD/NIST), **priorizados por EPSS e CISA KEV** (veja abaixo), com fallback para tabela local. Os CVEs vêm de busca por palavra-chave, então têm `confidence: low` (ou `medium` quando a KEV confirma o mesmo produto): valide a versão afetada |
| `waf` | Identifica **passivamente** WAF/CDN/balanceador (Cloudflare, Akamai, CloudFront, Fastly, Imperva, F5, Azure, ModSecurity e outros ~20) por headers, cookies e páginas de bloqueio, sem enviar payloads. Avisa que `Server` e versões pertencem à borda e que o scan pode estar sendo bloqueado |
| `ssl_tls` | Protocolo negociado, **versões TLS aceitas** (sonda TLS 1.0/1.1/1.2/1.3) e validade/expiração do certificado |
| `cors` | Origem arbitrária refletida, `Origin: null` e `*` com credenciais, com severidade conforme o impacto real |
| `exposed_files` | ~25 caminhos sensíveis (`.env`, `.git`, dumps SQL, chaves SSH, backups, Actuator, phpinfo...). **O conteúdo é validado por assinatura** (um 200 não basta), há baseline anti-soft-404 e **segredos são mascarados** na evidência |
| `misconfig` | HTTP sem redirecionar para HTTPS, `TRACE` habilitado (confirmado por eco), métodos de escrita em `Allow`, listagem de diretório, stack traces/debug em páginas de erro, `security.txt` |
| `subdomains` | Enumeração **passiva** via Certificate Transparency (crt.sh), resolução DNS, e alertas para nomes como `staging`/`admin`/`vpn` e subdomínios públicos apontando para IPs privados |
| `spf` | Existência, sintaxe básica, política final (`-all`/`~all`/`+all`) e limite de 10 consultas DNS |
| `dkim` | Seletores comuns publicados e chaves revogadas. Não conclusivo quando nada é achado: seletores personalizados não são enumeráveis |
| `dmarc` | Presença e política (`none`/`quarantine`/`reject`), `pct` e endereço de relatórios (`rua`) |
| `dnsbl` | Servidores de e-mail (MX) e domínio nas listas Spamhaus, SpamCop e Barracuda |

Todos os requests web passam por um cliente `httpx` assíncrono único (`scanner/http.py`) e uma falha em um check vira um finding informativo em vez de derrubar o scan.

## Achados acionáveis

Cada achado traz:

| Campo | Significado |
|---|---|
| `severity` | `critical`, `high`, `medium`, `low` ou `info` |
| `evidence` | O que foi observado (header, trecho de resposta, requisição). Segredos são mascarados |
| `remediation` | Passo concreto de correção |
| `cwe`, `references` | Classificação e links (OWASP, NVD...) |
| `confidence` | `high`, `medium` ou `low`: chance de ser um verdadeiro positivo. Achados `low` pedem validação manual |
| `rule_id`, `fingerprint` | Identificador da regra e hash estável para deduplicar entre execuções |

Critério de severidade: **critical** = segredo ou dado sensível comprovadamente acessível (`.env` com credenciais, chave privada, dump SQL, CVSS ≥ 9); **high** = exploração direta provável (CORS com credenciais, `.git` exposto, listagem com arquivos sensíveis, CVSS 7-8,9); **medium** = enfraquece defesas ou vaza informação útil (CSP ausente, sem redirect HTTPS, TRACE); **low** = hardening; **info** = confirmações e contexto.

### Priorização de CVEs: EPSS e CISA KEV

O CVSS mede a gravidade técnica, não a chance de uso real. Cada CVE encontrado é enriquecido com:

- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**: exploração ativa confirmada, com data de inclusão, prazo de correção e uso em ransomware.
- **[EPSS](https://www.first.org/epss/)** (FIRST): probabilidade de exploração nos próximos 30 dias.

| Condição | Efeito na severidade (só sobe, nunca desce) |
|---|---|
| Na KEV e CVSS ≥ 7 | `critical` |
| Na KEV e CVSS < 7 | no mínimo `high` |
| EPSS ≥ 50% | no mínimo `high` |
| EPSS ≥ 10% | no mínimo `medium` |

Os CVEs são ordenados por **KEV → EPSS → CVSS**, e só os 10 de maior prioridade por tecnologia aparecem. Assim um CVSS 7,5 com EPSS 97% passa à frente de um CVSS 9,8 com EPSS 0,1%. Ambas as fontes são gratuitas, ficam em cache por 24h e, se falharem, o scan segue com o CVSS e um achado informando. Para rodar offline: `WVS_THREAT_INTEL=0`.

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .          # instala os comandos `wvs` e `web-vuln-scanner`
pip install -e ".[api]"   # opcional: API web (FastAPI)
```

Requer Python 3.10+. Sem instalar, `pip install -r requirements.txt` e `python -m scanner.cli ...` também funcionam; abaixo `wvs` e `python -m scanner.cli` são equivalentes.

## Uso

```bash
# Tudo (web + e-mail/DNS + subdomínios): aceita URL ou domínio
python -m scanner.cli -t https://exemplo.com

# Só um módulo: web, email ou recon (subdomínios)
python -m scanner.cli -t https://exemplo.com -m web
python -m scanner.cli -t exemplo.com -m email
python -m scanner.cli -t exemplo.com -m recon

# Relatórios: o formato vem da extensão
python -m scanner.cli -t exemplo.com -o relatorio.md      # Markdown para o relatório de pentest
python -m scanner.cli -t exemplo.com -o resultado.json    # JSON versionado (schema_version)
python -m scanner.cli -t exemplo.com -o resultado.sarif   # SARIF 2.1.0
python -m scanner.cli -t exemplo.com -o relatorio.html

# Pentest com cuidado: ritmo baixo, proxy do Burp, identificação do engajamento
python -m scanner.cli -t https://cliente.com -m web --rate 2 --concurrency 4 \
    --proxy http://127.0.0.1:8080 --user-agent "ACME-Pentest/1.0" -H "X-Engagement: ACME-42"
```

| Opção | Descrição |
|---|---|
| `-t`, `--target` | URL ou domínio alvo (também aceito como argumento posicional) |
| `-m`, `--mode` | `web`, `email`, `recon` ou `full` (padrão) |
| `-o`, `--output` | Arquivo do relatório (`.json`, `.md`, `.sarif`, `.html`) |
| `-f`, `--format` | `text`, `json`, `md`, `sarif` ou `html` (sobrescreve a extensão; sem `-o`, imprime no console) |
| `--fail-on` | `critical`, `high` (padrão), `medium`, `low` ou `none`: severidade mínima para sair com código 2 (CI) |
| `--checks`, `--no-info`, `-v` | Checks web a executar, ocultar INFO, logs de depuração |
| `--list-checks` | Lista os checks disponíveis, incluindo plugins, e sai |
| `--baseline`, `--new-only` | Compara com um relatório JSON anterior; `--new-only` mostra e avalia `--fail-on` só nos achados novos |
| `--scope` | Arquivo com os alvos autorizados. O alvo e **toda requisição**, inclusive redirecionamentos, são verificados contra ele |
| `--allow-active` | Libera checks ativos/intrusivos (nenhum embutido por enquanto). **Exige `--scope`** e autorização expressa do dono do alvo |

**Rede e desempenho:**

| Opção | Descrição |
|---|---|
| `--rate` | Máximo de requisições por segundo no total (padrão 10; `0` = sem limite) |
| `--concurrency` | Requisições simultâneas (padrão 10) |
| `--retries` | Retentativas em timeout/429/502-504, com backoff exponencial e respeito a `Retry-After` (padrão 2) |
| `--timeout` | Timeout por requisição em segundos (padrão 10) |
| `--proxy` | `http://host:porta` ou `socks5://host:porta` |
| `-H`, `--header` | Header extra em todas as requisições (repetível) |
| `--user-agent` | Padrão: `web-vuln-scanner/<versão>`, que identifica a ferramenta |
| `--insecure` | Não valida o certificado do alvo (só diagnóstico) |

Se o alvo responde 429, bloqueia a maioria das requisições com 403/406 ou falha repetidamente, o scan **não insiste**: há retry com backoff, um circuit breaker por host e um achado informando que os resultados podem estar incompletos (reduza `--rate`). Timeouts, erros TLS e conexão recusada viram achados classificados, nunca um traceback.

Limitações: o `--proxy` cobre as requisições HTTP ao alvo e à crt.sh; a resolução DNS (subdomínios, SPF/DKIM/DMARC) e a consulta à NVD usam a rede direta.

### Escopo de engajamento (`--scope`)

Em um pentest, testar um host que não está no contrato é um problema jurídico, não só técnico. O arquivo de escopo faz a ferramenta **recusar** o que não foi autorizado:

```text
# escopo.txt (uma entrada por linha)
exemplo.com            # apenas este host
*.api.exemplo.com      # qualquer subdomínio (não inclui api.exemplo.com)
203.0.113.0/24         # faixa de IPs (casa com alvos informados como IP)
!interno.api.exemplo.com   # exclusão: vence qualquer inclusão
```

```bash
wvs -t https://exemplo.com --scope escopo.txt -o relatorio.md
```

- Alvo fora do escopo: a ferramenta sai com código 2 **antes de enviar qualquer requisição**.
- O escopo é imposto no cliente HTTP a cada requisição, **inclusive em cada salto de redirecionamento**: um `302` para um host não listado é bloqueado e o relatório avisa. Não há `--no-scope` nem como burlar por checks ou plugins, pois eles usam o mesmo cliente.
- Só a crt.sh (serviço público passivo, não é o alvo) fica fora da checagem.
- Limitações: entradas CIDR só casam com alvos dados como IP (um nome de domínio não é resolvido para conferir faixa); as consultas DNS (SPF/DKIM/DMARC e resolução de subdomínios) e a TLS direta ao alvo não passam pelo cliente HTTP.
- `--allow-active` só funciona junto de `--scope`.

### Comparação entre execuções (`--baseline`)

Compara com um relatório JSON anterior pelo `fingerprint` de cada achado e mostra o que é **novo**, o que **persiste** e o que foi **resolvido**:

```bash
wvs -t https://staging.exemplo.com -o base.json                    # primeira execução: guarda o baseline
wvs -t https://staging.exemplo.com --baseline base.json -o hoje.json
wvs -t https://staging.exemplo.com --baseline base.json --new-only --fail-on high   # CI: só falha por achado NOVO
```

Achados `info` não entram na comparação. Um achado que reaparece depois de corrigido conta como inalterado (já estava no baseline). Se o título de um achado muda (ex.: o EPSS de um CVE aparece no título), ele aparece como resolvido + novo, o que é uma mudança de risco que vale revisar. O SARIF recebe `baselineState` (`new`/`unchanged`) em cada resultado.

### Integração com CI/CD

```yaml
# GitHub Actions: falha o job com achados HIGH+ e publica o SARIF
- run: python -m scanner.cli -t https://staging.exemplo.com -m web -o resultado.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: resultado.sarif }
```

O SARIF omite achados `info`. Como o alvo é uma URL e não um arquivo do repositório, o GitHub mostra o alerta sem link para linha de código.

Use `fingerprint` (também em `partialFingerprints` do SARIF) para comparar execuções e alertar só sobre achados novos.

## API web (FastAPI)

```bash
uvicorn api.main:app --reload
curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" \
     -d '{"url":"https://exemplo.com","checks":["headers","cors"]}'
```

| Endpoint | Descrição |
|---|---|
| `POST /scan` | Executa o scan web (`{"url": "...", "checks": [...] }`, `checks` opcional) e retorna os findings em JSON. As severidades são `critical`/`high`/`medium`/`low`/`info` |
| `GET /checks` | Lista os módulos com uma descrição educativa de cada um |
| `GET /health` | Health check |

Documentação interativa em `http://localhost:8000/docs`.

### Integração com a NVD

O módulo `tech_detection` consulta a [NVD API](https://nvd.nist.gov/developers) do NIST (gratuita) por tecnologia + versão extraídas dos headers. A variável de ambiente `NVD_API_KEY` é **opcional, mas recomendada**: sem ela a API funciona com limite de requisições menor.

```bash
export NVD_API_KEY="sua-chave"   # chave gratuita: https://nvd.nist.gov/developers/request-an-api-key
```

Os resultados ficam em cache por 7 dias em `~/.cache/web-vuln-scanner/nvd_cache.json` (altere com `NVD_CACHE_PATH`). Se a NVD falhar, o scan continua com a tabela local e um finding INFO avisa da falha. Severidade CVSS: ≥ 9 crítico, ≥ 7 alto, ≥ 4 médio, abaixo disso baixo.

### ⚠️ Segurança ao expor a API

A API já implementa **rate limiting** (10 scans/minuto por IP, via slowapi) e **validação anti-SSRF** (rejeita localhost, IPs privados/link-local/reservados). Mesmo assim, a validação resolve o DNS só no momento da checagem (DNS rebinding ainda é possível). Expor a API publicamente, além de testes locais, exige também **autenticação** e, idealmente, isolamento de rede. Nunca a exponha sem isso: ela faz requisições a URLs escolhidas pelo usuário.

## Exemplo de saída

```
[CRÍTICO] Arquivo .env exposto com variáveis de ambiente
    GET https://exemplo.com/.env retornou HTTP 200 com 64 bytes e conteúdo compatível com o tipo de arquivo esperado.
    Evidência: APP_NAME=****
    Correção: Remova o arquivo do servidor web ou bloqueie o acesso (...). Considere os segredos comprometidos: revogue e rotacione-os.
[ALTO] Listagem de diretório habilitada em /uploads/
    Há arquivos sensíveis: dump.sql.
    Evidência: Entradas: dump.sql
[MÉDIO] Header Content-Security-Policy ausente
    ...

Resumo: CRÍTICO=1, ALTO=2, MÉDIO=2, BAIXO=3, INFO=5
```

## Plugins

Checks de terceiros se instalam como pacotes Python e aparecem sozinhos na CLI e na API, sem alterar este repositório:

```bash
pip install -e examples/wvs-plugin-cache-control
wvs --list-checks     # a coluna ORIGEM mostra plugin:cache_control
```

O mecanismo é o entry point `wvs.checks` apontando para um `CheckSpec` (`scanner/registry.py`). Plugins quebrados são ignorados com aviso. Guia completo, assinaturas e boas práticas em [CONTRIBUTING.md](CONTRIBUTING.md).

## Estrutura

```
web-vuln-scanner/
  scanner/
    finding.py   modelo Finding/Severity (evidência, CWE, confiança, fingerprint)
    http.py      cliente httpx async: rate limit, retry/backoff, proxy, circuit breaker
    registry.py  registro de checks e plugins (entry point wvs.checks)
    core.py      orquestração assíncrona dos checks e modos
    baseline.py  comparação entre execuções
    threatintel.py  EPSS e CISA KEV
    report.py    texto, JSON versionado, Markdown, SARIF 2.1.0, HTML
    scope.py     arquivo de escopo imposto a toda requisição
    cli.py   nvd.py
    checks/      headers, cookies, tech_detection, ssl_tls, cors, exposed_files,
                 misconfig, subdomains, email_dns
  api/           main.py   validation.py
  tests/         um arquivo por módulo (sem rede: httpx.MockTransport)
```

Testes: `pip install -r requirements-dev.txt && pytest tests -q`

## Roadmap

- [x] Integração real com a NVD para checar CVEs
- [x] API web (FastAPI)
- [x] Módulo de e-mail/DNS (SPF, DKIM, DMARC, DNSBL)
- [x] Modo assíncrono (`asyncio` + `httpx`), rate limit, retry, proxy
- [x] Relatórios Markdown, JSON versionado, SARIF e HTML
- [x] Enumeração passiva de subdomínios (crt.sh)
- [x] Priorização de CVEs com EPSS e CISA KEV
- [x] Detecção passiva de WAF/CDN
- [ ] Detecção ativa de WAF (requisição que provoca bloqueio), atrás de `--allow-active`
- [ ] Port scan (módulo ativo, atrás de `--allow-active` e arquivo de escopo)
- [x] Arquitetura de plugins (entry points) e `pyproject.toml`
- [x] Comparação entre execuções (`--baseline`)
- [x] Arquivo de escopo (`--scope`), exigido por `--allow-active`
- [x] CI no GitHub Actions (pytest em Python 3.10 a 3.14, mais o plugin de exemplo)

## Disclaimer

Esta ferramenta **não substitui um pentest profissional**. Ela detecta apenas problemas superficiais de configuração.

## Licença

MIT — veja [LICENSE](LICENSE).
