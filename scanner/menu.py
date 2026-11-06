"""Menu interativo (`goldani`): pergunta o essencial e chama scanner.cli, sem flags para memorizar.

Camada só de UX: pergunta (`gather_inputs`) e montagem dos argumentos (`build_argv`) são funções
puras e testáveis sem terminal de verdade; `main()` só as encadeia e entrega o resultado para
`scanner.cli.main`, que é quem de fato valida escopo, autorização e tudo o mais. O menu nunca
decide se um check ativo pode rodar — isso continua inteiramente em `scanner.cli`/`scanner.core`.
"""
import sys

from . import ui
from .cli import main as cli_main

MODE_CHOICES = {"1": "full", "2": "web", "3": "email", "4": "recon"}
FORMAT_EXT = {"2": "md", "3": "json", "4": "sarif", "5": "html"}
YES = ("s", "sim", "y", "yes")


def _ask(input_fn, prompt: str, default: str = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    raw = input_fn(f"{prompt}{suffix}: ").strip()
    return raw or (default or "")


def gather_inputs(console, input_fn=input) -> dict:
    """Pergunta o essencial (alvo, modo, checks ativos, saída) e devolve um dict simples."""
    target = ""
    while not target:
        target = _ask(input_fn, "Alvo (URL ou domínio, ex.: https://exemplo.com)")

    console.print("\n[bold]Modo do scan[/]")
    console.print("  1) Completo: web + e-mail/DNS + subdomínios  [padrão]")
    console.print("  2) Só web (headers, TLS, arquivos expostos, CORS...)")
    console.print("  3) Só e-mail/DNS (SPF, DKIM, DMARC, DNSBL)")
    console.print("  4) Só subdomínios (Certificate Transparency)")
    mode = MODE_CHOICES.get(_ask(input_fn, "Escolha", "1"), "full")

    console.print("\n[yellow]Port scan e sondagem ativa de WAF enviam tráfego fora do padrão de "
                  "navegação comum.[/] Use só em alvos que você tem autorização para testar "
                  "(seu laboratório ou um engajamento autorizado).")
    want_active = _ask(input_fn, "Habilitar esses checks ativos? (s/N)", "n").lower() in YES
    scope_path = ""
    if want_active:
        scope_path = _ask(input_fn, "Caminho do arquivo de escopo (uma linha por host autorizado)")
        if not scope_path:
            console.print("[dim]Sem arquivo de escopo, os checks ativos continuam desligados.[/]")
            want_active = False

    console.print("\n[bold]Salvar relatório em arquivo?[/]")
    console.print("  1) Não, só mostrar no terminal  [padrão]   2) Markdown   3) JSON   4) SARIF   5) HTML")
    fmt_choice = _ask(input_fn, "Escolha", "1")
    output = ""
    if fmt_choice in FORMAT_EXT:
        ext = FORMAT_EXT[fmt_choice]
        output = _ask(input_fn, "Nome do arquivo", f"relatorio.{ext}")

    return {"target": target, "mode": mode, "allow_active": want_active, "scope": scope_path,
           "output": output}


def build_argv(answers: dict) -> list:
    """Converte as respostas do menu nos mesmos argumentos que `wvs` aceitaria na linha de comando."""
    argv = ["-t", answers["target"], "-m", answers.get("mode") or "full", "--rich"]
    if answers.get("output"):
        argv += ["-o", answers["output"]]
    if answers.get("allow_active") and answers.get("scope"):
        argv += ["--scope", answers["scope"], "--allow-active"]
    return argv


def main(argv=None) -> int:
    console = ui.make_console()
    console.print(ui.Text(ui.BANNER, style="bold green"))
    console.print(f"  [bold green]{ui.TAGLINE}[/]  [dim]menu interativo · por Goldani[/]\n")
    try:
        answers = gather_inputs(console)
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Cancelado.[/]")
        return 1
    return cli_main(build_argv(answers))


if __name__ == "__main__":
    sys.exit(main())
