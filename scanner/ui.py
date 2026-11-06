"""Rich terminal interface (--rich): banner, per-check progress and a results table.

Presentation layer only: it never decides severity, filters findings, or changes scan behavior —
that is always `scanner.report` and `scanner.core`. Without `rich` installed, `scanner.cli` falls
back to plain text (`rich` is an optional dependency, only required with --rich).
"""
from datetime import datetime, timezone

from . import __version__
from .finding import Severity

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - only exercised when rich isn't installed
    RICH_AVAILABLE = False

BANNER = r"""
  ██████╗  ██████╗ ██╗     ██████╗   █████╗  ███╗   ██╗ ██╗
 ██╔════╝ ██╔═══██╗██║     ██╔══██╗ ██╔══██╗ ████╗  ██║ ██║
 ██║  ███╗██║   ██║██║     ██║  ██║ ███████║ ██╔██╗ ██║ ██║
 ██║   ██║██║   ██║██║     ██║  ██║ ██╔══██║ ██║╚██╗██║ ██║
 ╚██████╔╝╚██████╔╝███████╗██████╔╝ ██║  ██║ ██║ ╚████║ ██║
  ╚═════╝  ╚═════╝ ╚══════╝╚═════╝  ╚═╝  ╚═╝ ╚═╝  ╚═══╝ ╚═╝
"""
TAGLINE = "S C A N N E R"

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "dim",
}
EXPLOITABILITY_STYLE = {"high": "bold red", "moderate": "yellow", "low": "cyan", "informational": "dim"}


def make_console(no_color: bool = False) -> "Console":
    return Console(no_color=no_color, highlight=False, soft_wrap=False)


def print_banner(console, target: str, mode: str) -> None:
    console.print(Text(BANNER, style="bold green"), justify="left")
    console.print(f"  [bold green]{TAGLINE}[/]  [dim]v{__version__}[/]  ·  by Goldani", style="")
    console.print(f"  [dim]Target:[/] [bold]{target}[/]   [dim]Mode:[/] {mode}   "
                  f"[dim]Started:[/] {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S UTC}")
    console.print()


def make_progress(console) -> "Progress":
    return Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}", justify="left"),
        BarColumn(bar_width=20), TimeElapsedColumn(), console=console, transient=False,
    )


class ProgressReporter:
    """Synchronous callback (`on_event`) wired to an already-open `rich.progress.Progress`.

    Usage: pass `reporter.on_event` as `progress_cb` to `scan_target`/`scan_target_async`.
    """

    def __init__(self, progress: "Progress", planned: list):
        self.progress = progress
        self.tasks = {name: progress.add_task(f"[cyan]{name}[/] [dim](queued)[/]", total=1)
                     for name in planned}

    def on_event(self, event: str, name: str, *rest) -> None:
        task_id = self.tasks.get(name)
        if task_id is None:  # an unplanned check (e.g. a plugin discovered at runtime)
            task_id = self.progress.add_task(name, total=1)
            self.tasks[name] = task_id
        if event == "start":
            self.progress.update(task_id, description=f"[yellow]{name}[/] [dim](running…)[/]")
        elif event == "done":
            n = rest[0] if rest else 0
            style = "red" if n else "green"
            self.progress.update(task_id, completed=1,
                                 description=f"[{style}]{name}[/] ({n} finding(s))")


def severity_badge(counts: dict) -> str:
    return "   ".join(f"[{SEVERITY_STYLE[s]}]{s.label} {counts[s.value]}[/]" for s in SEVERITY_ORDER)


def print_results(console, findings, meta: dict) -> None:
    from .report import summary  # late import: avoids a cycle (report doesn't depend on ui)

    counts = summary(findings)
    console.print()
    console.print(Panel(severity_badge(counts), title="Summary",
                        subtitle=f"target: {meta.get('target', '-')}", border_style="green"))

    actionable = sorted((f for f in findings if f.severity is not Severity.INFO),
                        key=lambda f: -f.severity.rank)
    if not actionable:
        console.print("[dim]No actionable findings (besides INFO).[/]")
        return

    table = Table(expand=True, show_lines=False)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Finding", ratio=3)
    table.add_column("Exploitability", width=14, no_wrap=True)
    table.add_column("Check", width=14, no_wrap=True)
    for f in actionable:
        table.add_row(
            f"[{SEVERITY_STYLE[f.severity]}]{f.severity.label}[/]",
            f.title + (" [bold](NEW)[/]" if f.status == "new" else ""),
            f"[{EXPLOITABILITY_STYLE[f.exploitability]}]{f.exploitability}[/]",
            f.check,
        )
    console.print(table)
