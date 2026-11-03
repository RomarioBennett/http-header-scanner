"""Terminal rendering. Kept separate so the scanner has no display logic."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from .models import ScanResult, Status

STATUS_STYLE = {
    Status.PASS: "green",
    Status.WARN: "yellow",
    Status.FAIL: "red",
    Status.INFO: "cyan",
}
GRADE_STYLE = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bright_red",
}


def render(result: ScanResult, console: Console) -> None:
    # Header values come from the remote server, so they are untrusted.
    # escape() stops a hostile server injecting Rich markup into our output.
    table = Table(
        title=f"{escape(result.final_url)} (HTTP {result.status_code})",
        title_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Check", style="bold", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Sev.", no_wrap=True)
    table.add_column("Details", overflow="fold")

    for f in result.findings:
        style = STATUS_STYLE[f.status]
        detail = escape(f.detail)
        if f.value:
            detail += f"\n[dim]{escape(f.value)}[/dim]"
        table.add_row(
            f.title,
            f"[{style}]{f.status.value.upper()}[/{style}]",
            f.severity.value,
            detail,
        )
    console.print(table)

    if len(result.redirects) > 1:
        chain = " → ".join(escape(u) for u in result.redirects)
        console.print(f"[dim]Redirect chain:[/dim] {chain}")

    colour = GRADE_STYLE[result.grade]
    console.print(
        Panel(
            f"[bold {colour}]Grade {result.grade}[/bold {colour}]   "
            f"Score {result.score}/100   [dim]({result.elapsed_ms} ms)[/dim]",
            border_style=colour,
        )
    )

    todo = [f for f in result.findings if f.recommendation]
    if todo:
        console.print("[bold]Recommendations[/bold]")
        for f in todo:
            console.print(
                f"  • [yellow]{escape(f.title)}[/yellow]: {escape(f.recommendation or '')}"
            )
    console.print()
