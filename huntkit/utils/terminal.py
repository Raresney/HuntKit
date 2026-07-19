"""Shared Rich console + small presentation helpers.

A single `Console` instance is exported so every module renders through the
same terminal (consistent theming, one place to disable colour, correct
handling of concurrent progress bars). Windows legacy consoles are forced
onto the ANSI path with UTF-8 output so glyphs never raise.
"""

from __future__ import annotations

import sys
from typing import Iterable, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# Ensure Unicode never crashes a legacy Windows console (cp1252).
for _stream in (sys.stdout, sys.stderr):
    try:  # pragma: no cover - platform dependent
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HUNTKIT_THEME = Theme(
    {
        "info": "cyan",
        "ok": "bold green",
        "warn": "yellow",
        "error": "bold red",
        "step": "bold blue",
        "muted": "dim",
        "critical": "bold white on red",
        "high": "bold red",
        "medium": "yellow",
        "low": "green",
        "informational": "cyan",
    }
)

# legacy_windows=False forces the ANSI renderer instead of the win32 console
# API, which chokes on non-cp1252 glyphs.
console = Console(theme=HUNTKIT_THEME, legacy_windows=False)
err_console = Console(theme=HUNTKIT_THEME, legacy_windows=False, stderr=True)


def banner(text: str) -> None:
    console.print(Panel.fit(Text(text, style="bold cyan")))


def info(msg: str) -> None:
    console.print(f"[info]›[/info] {msg}")


def ok(msg: str) -> None:
    console.print(f"[ok]✓[/ok] {msg}")


def warn(msg: str) -> None:
    console.print(f"[warn]![/warn] {msg}")


def error(msg: str) -> None:
    err_console.print(f"[error]✗[/error] {msg}")


def step(msg: str) -> None:
    console.print(f"[step]»[/step] [bold]{msg}[/bold]")


def bullet(msg: str, style: str = "info") -> None:
    console.print(f"  [{style}]•[/{style}] {msg}")


def make_table(title: str, columns: Sequence[str]) -> Table:
    table = Table(title=title or None, title_style="bold", header_style="bold")
    for col in columns:
        table.add_column(col, overflow="fold")
    return table


def print_table(title: str, columns: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
    table = make_table(title, columns)
    for row in rows:
        table.add_row(*[str(c) for c in row])
    console.print(table)
