"""Terminal output helpers.

Uses `rich` when available for colour/tables, but degrades to plain
`print` so HuntKit still works on a bare Kali box with no extra deps.
"""

from __future__ import annotations

import sys
from typing import Iterable, Sequence

# Make sure Unicode glyphs never crash on a legacy Windows console (cp1252).
# On Kali/Linux this is a no-op; on Windows it swaps the encoder for a
# UTF-8 one that replaces unknown chars instead of raising.
for _stream in (sys.stdout, sys.stderr):
    try:  # pragma: no cover - platform dependent
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:  # pragma: no cover - presentation only
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    # legacy_windows=False forces the ANSI renderer instead of the win32
    # console API, which chokes on non-cp1252 glyphs.
    _console = Console(legacy_windows=False, safe_box=True)
    _RICH = True
except Exception:  # rich not installed
    _console = None
    _RICH = False


# ---- colour codes for the no-rich fallback -------------------------------
_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}


def _supports_ansi() -> bool:
    return sys.stdout.isatty()


def _c(text: str, colour: str) -> str:
    if _supports_ansi() and colour in _ANSI:
        return f"{_ANSI[colour]}{text}{_ANSI['reset']}"
    return text


def banner(text: str) -> None:
    if _RICH:
        _console.print(Panel.fit(Text(text, style="bold cyan")))
    else:
        line = "=" * (len(text) + 4)
        print(_c(line, "cyan"))
        print(_c(f"| {text} |", "cyan"))
        print(_c(line, "cyan"))


def info(msg: str) -> None:
    if _RICH:
        _console.print(f"[cyan]›[/cyan] {msg}")
    else:
        print(f"{_c('›', 'cyan')} {msg}")


def ok(msg: str) -> None:
    if _RICH:
        _console.print(f"[green]✓[/green] {msg}")
    else:
        print(f"{_c('[+]', 'green')} {msg}")


def warn(msg: str) -> None:
    if _RICH:
        _console.print(f"[yellow]![/yellow] {msg}")
    else:
        print(f"{_c('[!]', 'yellow')} {msg}")


def error(msg: str) -> None:
    if _RICH:
        _console.print(f"[red]✗[/red] {msg}")
    else:
        print(f"{_c('[-]', 'red')} {msg}", file=sys.stderr)


def step(msg: str) -> None:
    if _RICH:
        _console.print(f"[bold blue]»[/bold blue] [bold]{msg}[/bold]")
    else:
        print(_c(f"» {msg}", "blue"))


def bullet(msg: str, colour: str = "cyan") -> None:
    if _RICH:
        _console.print(f"  [{colour}]•[/{colour}] {msg}")
    else:
        print(f"  {_c('•', colour)} {msg}")


def table(title: str, columns: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
    rows = list(rows)
    if _RICH:
        t = Table(title=title, title_style="bold")
        for col in columns:
            t.add_column(col, overflow="fold")
        for row in rows:
            t.add_row(*[str(c) for c in row])
        _console.print(t)
        return

    # plain fallback
    widths = [len(c) for c in columns]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    if title:
        print(_c(title, "bold"))
    header = "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(columns))
    print(_c(header, "bold"))
    print("-" * len(header))
    for row in rows:
        print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
