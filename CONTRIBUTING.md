# Contribuindo

Obrigado por querer melhorar o web-vuln-scanner. Duas regras valem para tudo: **só módulos que respeitam
o escopo ético do projeto** (passivos por padrão; intrusivos exigem `active=True` e `--allow-active`) e
**nenhum teste pode depender de rede** (use `httpx.MockTransport`, veja `tests/conftest.py`).

## Ambiente

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests -q
```

## Escrevendo um check

Um check é uma função que devolve `list[Finding]` + um `CheckSpec` que a descreve.

| `kind` | Assinatura | Quando usar |
|---|---|---|
| `response` | `fn(response) -> list` | Analisar a resposta da página inicial (headers, cookies, corpo). Roda em thread |
| `async` | `async fn(ctx) -> list` | Fazer requisições extras com `ctx.client` (herda rate limit, retry, proxy) |
| `url` | `fn(url, timeout=) -> list` | Código bloqueante sobre a URL (sockets) |
| `domain` | `fn(domain, timeout=) -> list` | Código bloqueante sobre o domínio (DNS) |

`category` define o modo em que roda: `web`, `email` ou `recon` (recon só aceita `async`).

### Boas práticas para os `Finding`

- `severity`: `critical` = segredo/dado sensível comprovadamente acessível; `high` = exploração direta
  provável; `medium` = enfraquece defesas; `low` = hardening; `info` = confirmações e contexto.
- `evidence`: o que foi **observado**. **Nunca** inclua segredos: mascare valores (`DB_PASSWORD=****`).
- `remediation`: um passo concreto, não "melhore a segurança".
- `confidence`: `high` só se o achado foi validado (assinatura de conteúdo, eco confirmado). Heurísticas
  são `low`/`medium`.
- `rule_id` estável (`meucheck.regra`): vira o `ruleId` do SARIF. `cwe` e `references` quando houver.
- Evite falsos positivos: um status 200 não prova nada; valide o conteúdo.
- Use `ctx.client.request(...)` em vez de abrir conexões próprias e trate `RequestFailed`.

## Plugins externos (sem alterar este repositório)

Um plugin é um pacote que expõe um `CheckSpec` pelo entry point `wvs.checks`. Exemplo completo e
instalável em [`examples/wvs-plugin-cache-control`](examples/wvs-plugin-cache-control).

```python
# meu_plugin/__init__.py
from scanner.finding import Finding, Severity
from scanner.registry import CheckSpec

def check_meu_header(response):
    if "x-meu-header" in response.headers:
        return []
    return [Finding("meu_header", Severity.LOW, "X-Meu-Header ausente",
                    remediation="Adicione o header.", rule_id="meu_header.missing")]

SPEC = CheckSpec(name="meu_header", kind="response", func=check_meu_header,
                 category="web", description="Exige o header X-Meu-Header.")
```

```toml
# pyproject.toml do plugin
[project.entry-points."wvs.checks"]
meu_header = "meu_plugin:SPEC"
```

Depois de `pip install`, confira com `wvs --list-checks` (a coluna ORIGEM mostra `plugin:<nome>`).
Um entry point pode apontar também para uma **lista** de `CheckSpec`. Plugins que falham ao carregar,
têm nome repetido ou não apontam para um `CheckSpec` são **ignorados com um aviso**: nunca derrubam o scan.

## Checks ativos

Qualquer check que envie tráfego intrusivo (payloads, varredura de portas) deve declarar `active=True`.
Ele fica fora dos padrões e só roda com `--allow-active`, para que ninguém dispare um teste intrusivo sem
querer. Use apenas em alvos com autorização expressa.

## Pull requests

Commits no estilo [Conventional Commits](https://www.conventionalcommits.org/) (`feat(waf): ...`),
testes para o comportamento novo e README atualizado quando mudar a CLI ou a saída.
