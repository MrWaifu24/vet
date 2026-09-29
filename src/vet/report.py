"""Terminal rendering of analysis reports."""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .models import Report, Severity

SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
}

VERDICT_STYLE = {
    "CLEAN": "bold green",
    "LOW RISK": "bold green",
    "SUSPICIOUS": "bold yellow",
    "HIGH RISK": "bold white on red",
}

CODE_LEXER = {"vba_macro": "vbnet", "xlm_macro": "text", "javascript": "javascript"}
PREVIEW_LINES = 40


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def render(report: Report, console: Console, show_code: bool = False) -> None:
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="dim")
    summary.add_column(overflow="fold")
    summary.add_row("File", report.path)
    summary.add_row("Type", report.file_type)
    summary.add_row("Size", f"{human_size(report.size)} ({report.size:,} bytes)")
    for algo, digest in report.hashes.items():
        summary.add_row(algo.upper(), digest)
    summary.add_row("Entropy", f"{report.entropy:.2f} bits/byte")
    verdict = Text(f" {report.verdict} ", style=VERDICT_STYLE[report.verdict])
    summary.add_row("Verdict", verdict)
    console.print(
        Panel(summary, title="[bold]vet[/] file triage", title_align="left", box=box.ROUNDED)
    )

    if report.metadata:
        meta = Table(
            box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan", title_justify="left"
        )
        meta.add_column("Metadata")
        meta.add_column("Value", overflow="fold")
        for k, v in report.metadata.items():
            meta.add_row(k, v)
        console.print(meta)

    if report.keywords:
        kw = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
        kw.add_column("PDF keyword")
        kw.add_column("Count", justify="right")
        for k, v in report.keywords.items():
            kw.add_row(k, str(v))
        console.print(kw)

    findings = report.sorted_findings()
    if findings:
        ft = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", show_lines=False)
        ft.add_column("Severity", no_wrap=True)
        ft.add_column("Finding", overflow="fold")
        ft.add_column("ATT&CK", no_wrap=True, style="yellow")
        for f in findings:
            body = Text(f.title, style="bold")
            if f.detail:
                body.append("\n" + f.detail, style="default")
            ft.add_row(Text(f.severity.name, style=SEVERITY_STYLE[f.severity]), body, f.attack)
        console.print(ft)
    else:
        console.print("[green]No findings.[/]\n")

    if report.artifacts:
        console.print(Text("  Extracted artifacts", style="bold cyan"))
        for a in report.artifacts:
            line = Text("  • ")
            line.append(a.kind, style="bold")
            line.append(f"  {a.name}  ")
            line.append(f"({human_size(a.size)})", style="dim")
            console.print(line)
            console.print(Text(f"      sha256  {a.sha256}", style="default"), overflow="fold")
            if a.notes:
                console.print(Text(f"      notes   {a.notes}", style="dim"), overflow="fold")
            if a.saved_to:
                console.print(Text(f"      saved   {a.saved_to}", style="green"), overflow="fold")
        if not any(a.saved_to for a in report.artifacts):
            console.print(
                "[dim]  Use --extract DIR to save artifacts, "
                "--show-code to print macro/script source.[/]"
            )
        console.print()

    if show_code:
        for a in report.artifacts:
            if a.content is None:
                continue
            lines = a.content.splitlines()
            code = "\n".join(lines[:PREVIEW_LINES])
            parts = [
                Syntax(code, CODE_LEXER.get(a.kind, "text"), line_numbers=True, word_wrap=True)
            ]
            if len(lines) > PREVIEW_LINES:
                parts.append(Text(f"... {len(lines) - PREVIEW_LINES} more line(s)", style="dim"))
            console.print(Panel(Group(*parts), title=f"{a.kind}: {a.name}", title_align="left"))

    for err in report.errors:
        console.print(f"[dim red]warning:[/] [dim]{err}[/]")
