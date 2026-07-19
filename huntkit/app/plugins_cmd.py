"""`huntkit plugins` — browse the tool plugins HuntKit can drive."""

from __future__ import annotations

from typing import Optional

import typer

from ..plugins import Category
from ..utils import terminal as term

plugins_app = typer.Typer(no_args_is_help=True, help="Browse and inspect tool plugins.")


def _status(available: bool) -> str:
    return "[ok]installed[/ok]" if available else "[muted]missing[/muted]"


@plugins_app.command("list")
def plugins_list(
    ctx: typer.Context,
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by category (discovery/resolve/ports/urls/scan)."
    ),
    available_only: bool = typer.Option(
        False, "--available", "-a", help="Show only installed tools."
    ),
) -> None:
    """List plugins, their capability chain, and install status."""
    app_ctx = ctx.obj
    registry, runner = app_ctx.registry, app_ctx.runner

    plugins = registry.all()
    if category:
        try:
            plugins = registry.by_category(Category(category))
        except ValueError:
            term.error(f"unknown category: {category}")
            raise typer.Exit(2) from None
    if available_only:
        plugins = [p for p in plugins if p.is_available(runner)]

    table = term.make_table("Plugins", ["tool", "category", "consumes", "produces", "status"])
    for p in plugins:
        table.add_row(
            p.name,
            p.category.value,
            p.consumes.value if p.consumes else "-",
            p.produces.value,
            _status(p.is_available(runner)),
        )
    term.console.print(table)
    installed = len(registry.available(runner))
    term.info(f"{installed}/{len(registry)} tools installed.")


@plugins_app.command("show")
def plugins_show(ctx: typer.Context, name: str = typer.Argument(..., help="Plugin name.")) -> None:
    """Show one plugin's metadata and how to install it."""
    app_ctx = ctx.obj
    plugin = app_ctx.registry.get(name)
    if plugin is None:
        term.error(f"no such plugin: {name}")
        raise typer.Exit(2)
    available = plugin.is_available(app_ctx.runner)
    rows = [
        ("name", plugin.name),
        ("category", plugin.category.value),
        ("description", plugin.description or "-"),
        ("consumes", plugin.consumes.value if plugin.consumes else "-"),
        ("produces", plugin.produces.value),
        ("input mode", plugin.input_mode.value),
        ("status", "installed" if available else "missing"),
    ]
    if plugin.needs_api_key:
        rows.append(("api key", plugin.needs_api_key))
    if not available:
        rows.append(("install", plugin.install))
    term.print_table(f"plugin: {plugin.name}", ["field", "value"], rows)
