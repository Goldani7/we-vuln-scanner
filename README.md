# web-vuln-scanner

Scanner de segurança **passivo e não-invasivo** para aplicações web, feito para fins de portfólio. Realiza apenas requisições `GET`/`HEAD` comuns — sem brute-force, sem exploração ativa e sem wordlists de diretório.

## ⚠️ Aviso ético

Use esta ferramenta **somente em sistemas que você possui ou para os quais tem autorização explícita** para testar. O acesso não autorizado a sistemas é crime: no Brasil, a Lei 12.737/2012 (Lei Carolina Dieckmann) tipifica a invasão de dispositivos informáticos; nos EUA, o Computer Fraud and Abuse Act (CFAA) tem efeito semelhante. O autor não se responsabiliza pelo uso indevido.

## Módulos de verificação

| Módulo | O que verifica |
|---|---|
| `headers` | Presença de CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `cookies` | Flags Secure, HttpOnly e SameSite |
| `tech_detection` | Exposição de `Server`/`X-Powered-By` e versões possivelmente desatualizadas |
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
    finding.py   core.py   report.py   cli.py
    checks/      headers, ssl_tls, cookies, cors, exposed_files, tech_detection
  tests/
    test_headers.py
```

Testes: `pytest tests/ -q`

## Roadmap

- [ ] Enumeração de subdomínios via crt.sh
- [ ] Integração real com a NVD para checar CVEs
- [ ] Relatório em PDF/HTML
- [ ] Modo assíncrono

## Disclaimer

Esta ferramenta **não substitui um pentest profissional**. Ela detecta apenas problemas superficiais de configuração.

## Licença

MIT — veja [LICENSE](LICENSE).
