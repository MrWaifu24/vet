"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console

from . import __version__
from .analyzer import analyze
from .models import Severity
from .report import render

EXIT_OK, EXIT_SUSPICIOUS, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vet",
        description=(
            "File triage for SOC analysts: extract VBA/XLM macros from Office documents, "
            "and metadata, JavaScript and embedded files from PDFs."
        ),
        epilog=("exit status: 0 = clean/low risk, 1 = suspicious or high-risk findings, 2 = error"),
    )
    p.add_argument("files", nargs="+", type=Path, metavar="FILE", help="file(s) to analyze")
    p.add_argument("--json", action="store_true", help="print a JSON report instead of tables")
    p.add_argument(
        "-x",
        "--extract",
        type=Path,
        metavar="DIR",
        help="save macros, scripts and embedded files under DIR/<file-name>/ "
        "(binary payloads get a .vet suffix so they cannot be double-clicked)",
    )
    p.add_argument(
        "-s", "--show-code", action="store_true", help="print extracted macro/script source"
    )
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-V", "--version", action="version", version=f"vet {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(no_color=args.no_color, highlight=False)
    err_console = Console(stderr=True, no_color=args.no_color, highlight=False)

    status = EXIT_OK
    results = []
    for path in args.files:
        if not path.is_file():
            err_console.print(f"[red]vet: {path}: not a file[/]")
            status = EXIT_ERROR
            continue
        try:
            report = analyze(path, args.extract)
        except OSError as exc:
            err_console.print(f"[red]vet: {path}: {exc}[/]")
            status = EXIT_ERROR
            continue

        if report.max_severity >= Severity.MEDIUM and status == EXIT_OK:
            status = EXIT_SUSPICIOUS

        if args.json:
            results.append(report.to_dict())
        else:
            render(report, console, show_code=args.show_code)

    if args.json:
        payload = results[0] if len(results) == 1 else results
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    return status


if __name__ == "__main__":
    sys.exit(main())
