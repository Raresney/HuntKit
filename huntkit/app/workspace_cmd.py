"""`huntkit workspace` — list and inspect engagement workspaces."""

from __future__ import annotations

import typer

from ..core.workspace import Workspace, default_base, list_workspaces
from ..utils import terminal as term

workspace_app = typer.Typer(no_args_is_help=True, help="List and inspect workspaces.")


@workspace_app.command("list")
def workspace_list(ctx: typer.Context) -> None:
    """List every workspace under the workspace root."""
    app_ctx = ctx.obj
    base = app_ctx.base or default_base(app_ctx.config)
    names = list_workspaces(base=base)
    if not names:
        term.warn(f"no workspaces yet under {base}")
        term.info("create one with:  huntkit init <program> -s <domain>")
        return
    rows = []
    for name in names:
        ws = Workspace.open(name, config=app_ctx.config, base=app_ctx.base)
        subs = ws.count("recon/subdomains.txt")
        live = ws.count("recon/live.txt")
        rows.append((name, str(subs), str(live), str(len(ws.scope_in))))
    term.print_table(f"Workspaces ({base})", ["program", "subs", "live", "scope"], rows)


@workspace_app.command("show")
def workspace_show(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="Workspace / program name."),
) -> None:
    """Show scope, counts, and stage status for one workspace."""
    app_ctx = ctx.obj
    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)
    if not ws.has_scope() and not ws.state.counts:
        term.warn(f"workspace '{program}' looks empty ({ws.root})")

    term.banner(f"workspace: {program}")
    term.info(f"path: {ws.root}")

    scope_in = ws.scope_in or ["(none — everything in scope)"]
    term.step("Scope")
    for entry in scope_in:
        term.bullet(entry, style="ok")
    for entry in ws.scope_out:
        term.bullet(f"{entry}  (excluded)", style="warn")

    if ws.state.counts:
        term.print_table("Assets", ["metric", "count"],
                         [(k, str(v)) for k, v in ws.state.counts.items()])
    if ws.state.stages:
        rows = []
        for name, rec in ws.state.stages.items():
            dur = f"{rec.duration:.1f}s" if rec.duration else "-"
            rows.append((name, rec.status.value, dur))
        term.print_table("Stages", ["stage", "status", "time"], rows)
