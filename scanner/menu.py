"""Interactive menu (`goldani`): asks the essentials and calls scanner.cli — no flags to memorize.

UI layer only: gathering input (`gather_inputs`) and building the argument list (`build_argv`) are
pure, testable functions that need no real terminal; `main()` just chains them and hands the result
to `scanner.cli.main`, which is what actually validates scope, authorization, and everything else.
The menu never decides whether an active check is allowed to run — that stays entirely in
`scanner.cli`/`scanner.core`.
"""
import sys

from . import ui
from .cli import main as cli_main

MODE_CHOICES = {"1": "full", "2": "web", "3": "email", "4": "recon"}
FORMAT_EXT = {"2": "md", "3": "json", "4": "sarif", "5": "html"}
YES = ("y", "yes")


def _ask(input_fn, prompt: str, default: str = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    raw = input_fn(f"{prompt}{suffix}: ").strip()
    return raw or (default or "")


def gather_inputs(console, input_fn=input) -> dict:
    """Asks the essentials (target, mode, active checks, output) and returns a plain dict."""
    target = ""
    while not target:
        target = _ask(input_fn, "Target (URL or domain, e.g. https://example.com)")

    console.print("\n[bold]Scan mode[/]")
    console.print("  1) Full: web + email/DNS + subdomains  [default]")
    console.print("  2) Web only (headers, TLS, exposed files, CORS...)")
    console.print("  3) Email/DNS only (SPF, DKIM, DMARC, DNSBL)")
    console.print("  4) Subdomains only (Certificate Transparency)")
    mode = MODE_CHOICES.get(_ask(input_fn, "Choice", "1"), "full")

    console.print("\n[yellow]Port scanning and active WAF probing send traffic outside normal "
                  "browsing patterns.[/] Only use them against targets you're authorized to test "
                  "(your own lab, or an authorized engagement).")
    want_active = _ask(input_fn, "Enable those active checks? (y/N)", "n").lower() in YES
    scope_path = ""
    if want_active:
        scope_path = _ask(input_fn, "Path to the scope file (one authorized host per line)")
        if not scope_path:
            console.print("[dim]Without a scope file, active checks stay disabled.[/]")
            want_active = False

    console.print("\n[bold]Save the report to a file?[/]")
    console.print("  1) No, just show it in the terminal  [default]   2) Markdown   3) JSON   4) SARIF   5) HTML")
    fmt_choice = _ask(input_fn, "Choice", "1")
    output = ""
    if fmt_choice in FORMAT_EXT:
        ext = FORMAT_EXT[fmt_choice]
        output = _ask(input_fn, "File name", f"report.{ext}")

    return {"target": target, "mode": mode, "allow_active": want_active, "scope": scope_path,
           "output": output}


def build_argv(answers: dict) -> list:
    """Turns the menu's answers into the same arguments `wvs` would accept on the command line."""
    argv = ["-t", answers["target"], "-m", answers.get("mode") or "full", "--rich"]
    if answers.get("output"):
        argv += ["-o", answers["output"]]
    if answers.get("allow_active") and answers.get("scope"):
        argv += ["--scope", answers["scope"], "--allow-active"]
    return argv


def main(argv=None) -> int:
    console = ui.make_console()
    console.print(ui.Text(ui.BANNER, style="bold green"))
    console.print(f"  [bold green]{ui.TAGLINE}[/]  [dim]interactive menu · by Goldani[/]\n")
    try:
        answers = gather_inputs(console)
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Cancelled.[/]")
        return 1
    return cli_main(build_argv(answers))


if __name__ == "__main__":
    sys.exit(main())
