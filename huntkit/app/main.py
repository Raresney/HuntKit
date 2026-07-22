"""The HuntKit Typer application.

Defines the root command group, its global options, and the top-level
commands. Grouped commands (config/plugins/workspace) live in their own
modules and are mounted here. Run it with ``python -m huntkit`` or, once the
new interface reaches parity, the ``huntkit`` console script.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.markup import escape

from .. import __version__
from ..core.workspace import Workspace, list_workspaces
from ..intel import IntelReport, Priority, analyze as run_analyze, save_report
from ..knowledge import Playbook, all_playbooks, get_playbook
from ..pipeline import RECON_STAGES, ReconSummary, run_recon
from ..report import FORMATS, build as report_build, normalise_format, write as report_write
from ..utils import terminal as term
from ..utils import validators as v
from .config_cmd import config_app
from .context import AppContext
from .plugins_cmd import plugins_app
from .workspace_cmd import workspace_app

app = typer.Typer(
    name="huntkit",
    help="Local-first bug bounty recon, methodology & workflow framework.",
    no_args_is_help=True,
    add_completion=True,
    rich_markup_mode="rich",
)
app.add_typer(config_app, name="config")
app.add_typer(plugins_app, name="plugins")
app.add_typer(workspace_app, name="workspace")


def _version_cb(value: bool) -> None:
    if value:
        term.console.print(f"HuntKit {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    ctx: typer.Context,
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to a huntkit.yaml.", metavar="PATH"
    ),
    workspace: Optional[Path] = typer.Option(
        None, "--workspace", "-w", help="Workspace base dir (default ~/.huntkit).",
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose (debug) logging."),
    quiet: bool = typer.Option(False, "--quiet", help="Errors only."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable coloured output."),
    _version: bool = typer.Option(
        False, "--version", callback=_version_cb, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Build the shared context every command reads from."""
    if no_color:
        term.console.no_color = True
        term.err_console.no_color = True
    ctx.obj = AppContext.build(
        config_path=config, workspace=workspace, verbose=verbose, quiet=quiet
    )


# --------------------------------------------------------------------------
# version
# --------------------------------------------------------------------------
@app.command()
def version() -> None:
    """Print the HuntKit version."""
    term.console.print(f"HuntKit {__version__}")


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------
@app.command()
def doctor(ctx: typer.Context) -> None:
    """Check which tools are installed and where HuntKit stores data."""
    app_ctx = ctx.obj
    registry, runner = app_ctx.registry, app_ctx.runner

    term.banner("HuntKit doctor — toolchain check")
    table = term.make_table("", ["tool", "category", "status", "path / install"])
    missing = 0
    for p in registry.all():
        path = runner.resolve(p.name)
        if path:
            table.add_row(p.name, p.category.value, "[ok]installed[/ok]", path)
        else:
            missing += 1
            table.add_row(p.name, p.category.value, "[warn]missing[/warn]", p.install)
    term.console.print(table)

    if missing:
        term.warn(f"{missing}/{len(registry)} tools missing — those stages are skipped, "
                  "HuntKit still runs.")
    else:
        term.ok("full toolchain present.")
    term.info(f"workspace root: {app_ctx.config.workspace_root}")
    if app_ctx.config._sources:
        term.info("config: " + ", ".join(app_ctx.config._sources))


# --------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------
@app.command()
def init(
    ctx: typer.Context,
    program: str = typer.Argument(..., help="A name for this engagement/workspace."),
    scope: Optional[list[str]] = typer.Option(
        None, "--scope", "-s", help="In-scope domain, IP, CIDR, or *.wildcard (repeatable)."
    ),
    out: Optional[list[str]] = typer.Option(
        None, "--out", "-x", help="Out-of-scope pattern (repeatable)."
    ),
) -> None:
    """Create a workspace and set its scope."""
    app_ctx = ctx.obj
    scope = scope or []
    out = out or []

    bad = [s for s in (*scope, *out) if not v.is_scope_entry(s)]
    if bad:
        term.error("invalid scope entries: " + ", ".join(bad))
        term.info("use a domain, IP, CIDR, or a *.wildcard.")
        raise typer.Exit(2)

    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)
    if scope or out:
        ws.set_scope(scope, out)

    term.ok(f"workspace ready: {ws.root}")
    if scope:
        term.info("in-scope: " + ", ".join(scope))
    if v.is_wildcard_scope_risky(scope):
        term.warn("broad wildcard scope — double-check the program allows it before scanning.")
    seed = next((s.lstrip("*.") for s in scope if v.is_domain(s.lstrip("*."))), "<domain>")
    term.info(f"next:  huntkit recon {seed} -p {program}")


# --------------------------------------------------------------------------
# recon
# --------------------------------------------------------------------------
def _render_event(event: dict) -> None:
    kind = event.get("event")
    if kind == "stage_start":
        term.step(f"stage: {event['stage']}")
    elif kind == "stage_resumed":
        term.info(f"  {event['stage']}: already done — resumed (use --fresh to re-run)")
    elif kind == "plugin_done":
        term.bullet(f"{event['plugin']}: {event['found']} found", "ok")
    elif kind == "plugin_skip":
        term.bullet(f"{event['plugin']}: skipped ({event['reason']})", "muted")
    elif kind == "stage_done":
        if not event["ran"]:
            term.warn(f"  {event['stage']}: no tool ran — install one to enable this stage")
        else:
            term.info(f"  {event['stage']}: +{event['new']} new, {event['total']} total")


@app.command()
def recon(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="Seed domain, e.g. example.com."),
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Workspace to use (default: the domain)."
    ),
    stage: str = typer.Option(
        "all", "--stage", "-s", help="all | subs | resolve | live | ports | urls."
    ),
    threads: Optional[int] = typer.Option(
        None, "--threads", "-t", help="Concurrency (default: config general.threads)."
    ),
    fresh: bool = typer.Option(
        False, "--fresh", help="Ignore saved progress and re-run every stage."
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Bypass the tool-output cache for this run."
    ),
) -> None:
    """Run the recon pipeline: subdomains -> resolve -> live -> ports -> urls."""
    app_ctx = ctx.obj
    try:
        domain = v.normalise_domain(domain)
    except v.ValidationError:
        term.error(f"not a valid domain: {domain}")
        raise typer.Exit(2) from None

    if stage != "all" and stage not in RECON_STAGES:
        term.error(f"unknown stage: {stage} (choose all/{'/'.join(RECON_STAGES)})")
        raise typer.Exit(2)

    program = program or _pick_program(app_ctx, default=domain)
    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)

    if ws.has_scope():
        if not ws.in_scope(domain):
            term.error(f"{domain} is out of scope for '{program}'.")
            term.info(f"add it:  huntkit init {program} -s {domain}")
            raise typer.Exit(2)
    else:
        # bound an un-scoped run to the target's own tree, and say so
        ws.set_scope([f"*.{domain}"], [])
        term.warn(f"no scope set — limiting to *.{domain}. Refine with `huntkit init`.")

    if fresh:
        ws.state.reset()

    term.banner(f"recon {domain}  ->  {program}")
    stages = None if stage == "all" else [stage]
    summary = run_recon(
        ws, app_ctx.config, domain,
        stages=stages, resume=not fresh,
        runner=app_ctx.runner, registry=app_ctx.registry,
        on_event=_render_event, threads=threads, use_cache=not no_cache,
    )
    _print_summary(summary, ws)


def _pick_program(app_ctx: AppContext, default: str) -> str:
    """Reuse the only existing workspace if there is exactly one, else `default`."""
    existing = list_workspaces(base=app_ctx.base, config=app_ctx.config)
    return existing[0] if len(existing) == 1 else default


def _print_summary(summary: ReconSummary, ws: Workspace) -> None:
    rows = []
    for s in summary.stages:
        tools = "resumed" if s.resumed else (", ".join(s.ran) or "-")
        rows.append((s.stage, str(s.new), str(s.total), tools))
    term.print_table("Recon summary", ["stage", "new", "total", "tools"], rows)
    term.ok(f"{summary.total_new} new assets. Files under {ws.root}")


# --------------------------------------------------------------------------
# analyze
# --------------------------------------------------------------------------
@app.command()
def analyze(
    ctx: typer.Context,
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Workspace to analyse (default: the only one)."
    ),
    top: int = typer.Option(15, "--top", "-n", help="How many hosts / paths to show."),
) -> None:
    """Score the recon surface into prioritised hosts and attack paths."""
    app_ctx = ctx.obj
    program = program or _pick_program(app_ctx, default="")
    if not program:
        term.error("which workspace? pass -p <program> (none, or several, found).")
        raise typer.Exit(2)

    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)
    report = run_analyze(ws)

    if not report.signals:
        term.warn(f"no signals for '{program}' — thin or ungathered recon surface.")
        term.info(f"gather more:  huntkit recon <domain> -p {program}  (urls & ports help most)")
        raise typer.Exit(0)

    term.banner(f"intel — {program}")
    term.info("hosts by priority: " + "  ".join(
        f"[{p.style}]{p.label}[/{p.style}] {report.summary[p.label]}"
        for p in sorted(Priority, reverse=True) if report.summary[p.label]
    ))

    rows = []
    for h in report.hosts[:top]:
        pr = h.priority
        rows.append((
            h.host, f"[{pr.style}]{pr.label}[/{pr.style}]",
            str(h.score), str(len(h.signals)),
            ", ".join(h.playbooks[:4]) or "-",
        ))
    term.print_table("Prioritised hosts", ["host", "priority", "score", "signals", "playbooks"], rows)

    _print_notable(report, top)
    _print_attack_paths(report, top)

    path = save_report(ws, report)
    term.ok(f"{len(report.signals)} signals across {len(report.hosts)} hosts — wrote {path}")


def _print_notable(report: IntelReport, top: int) -> None:
    """High/Critical single signals — infra exposures that drive priority."""
    hot = sorted(
        (s for s in report.signals if int(s.severity) >= 4),
        key=lambda s: (-int(s.severity), s.host),
    )
    if not hot:
        return
    rows = [
        (f"[{s.severity.style}]{s.severity.label}[/{s.severity.style}]",
         s.host, s.title, s.evidence)
        for s in hot[:top]
    ]
    term.print_table("Notable exposures", ["severity", "host", "finding", "evidence"], rows)


def _print_attack_paths(report: IntelReport, top: int) -> None:
    paths = report.attack_paths()
    if not paths:
        return
    rows = []
    for p in paths[:top]:
        where = ", ".join(p.hosts[:3]) + ("  …" if len(p.hosts) > 3 else "")
        rows.append((
            p.playbook, p.name,
            f"[{p.severity.style}]{p.severity.label}[/{p.severity.style}]",
            str(len(p.hosts)), where,
        ))
    term.print_table("Attack paths (highest impact first)",
                     ["id", "playbook", "severity", "hosts", "where"], rows)
    term.info("open a playbook for the how-to:  huntkit playbook <id>")


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------
@app.command()
def report(
    ctx: typer.Context,
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Workspace to report on (default: the only one)."
    ),
    fmt: str = typer.Option("md", "--format", "-f", help="md | html | json | pdf."),
    out: Optional[Path] = typer.Option(
        None, "--out", "-o", help="Write here instead of the workspace reports/ dir."
    ),
) -> None:
    """Write an engagement report (recon + intel + playbooks) to a file."""
    app_ctx = ctx.obj
    canonical = normalise_format(fmt)
    if canonical is None:
        term.error(f"unknown format: {fmt}")
        term.info("choose one:  " + " | ".join(FORMATS))
        raise typer.Exit(2)

    program = program or _pick_program(app_ctx, default="")
    if not program:
        term.error("which workspace? pass -p <program> (none, or several, found).")
        raise typer.Exit(2)

    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)
    rep = report_build(ws)
    if not rep.has_data:
        term.warn(f"nothing to report for '{program}' — no recon gathered yet.")
        term.info(f"run:  huntkit recon <domain> -p {program}")
        raise typer.Exit(0)

    written = report_write(ws, rep, canonical, out)

    term.banner(f"report — {program}")
    intel = rep.intel
    if intel.signals:
        term.info("hosts by priority: " + "  ".join(
            f"[{p.style}]{p.label}[/{p.style}] {intel.summary[p.label]}"
            for p in sorted(Priority, reverse=True) if intel.summary[p.label]
        ))
    term.ok(f"{canonical} report → {written.path}")
    if written.note:
        term.warn(written.note)


# --------------------------------------------------------------------------
# playbook (knowledge base)
# --------------------------------------------------------------------------
@app.command()
def playbook(
    name: Optional[str] = typer.Argument(
        None, help="Bug-class id (e.g. ssrf). Omit to list every playbook."
    ),
    md: bool = typer.Option(
        False, "--md", help="Print raw Markdown (for reports / copy-paste)."
    ),
) -> None:
    """Show a bug-class playbook: how to find it, payloads, bypasses, refs."""
    if not name:
        _list_playbooks()
        return
    pb = get_playbook(name)
    if pb is None:
        term.error(f"unknown playbook '{name}'.")
        term.info("pick one:  " + ", ".join(p.id for p in all_playbooks()))
        raise typer.Exit(2)
    if md:
        # raw markdown straight to stdout — no Rich wrapping/markup so long
        # payload lines stay intact and it copy-pastes clean into a report
        typer.echo(pb.to_markdown())
        return
    _render_playbook(pb)


def _list_playbooks() -> None:
    term.banner("HuntKit playbooks")
    rows = [
        (p.id, f"[{p.severity.style}]{p.severity.label}[/{p.severity.style}]", p.title, p.summary)
        for p in all_playbooks()
    ]
    term.print_table("Bug-class knowledge base", ["id", "severity", "class", "what it is"], rows)
    term.info("detail:  huntkit playbook <id>      e.g.  huntkit playbook ssrf")


def _render_playbook(pb: Playbook) -> None:
    term.banner(pb.title)
    term.info(
        f"severity [{pb.severity.style}]{pb.severity.label}[/{pb.severity.style}]"
        f"  ·  id [bold]{pb.id}[/bold]"
    )
    term.console.print(pb.summary)
    term.console.print(f"[muted]when:[/muted] {escape(pb.when)}")

    if pb.detection:
        term.step("Detection")
        for i, item in enumerate(pb.detection, 1):
            term.bullet(f"{i}. {escape(item)}")
    if pb.payloads:
        term.step("Payloads")
        for p in pb.payloads:
            term.console.print(f"    [muted]›[/muted] {escape(p)}")
    if pb.bypasses:
        term.step("Bypasses")
        for b in pb.bypasses:
            term.bullet(escape(b), "muted")
    if pb.tools:
        term.step("Go-to tools")
        term.bullet(", ".join(pb.tools), "ok")
    if pb.references:
        term.step("References")
        for r in pb.references:
            term.bullet(f"{escape(r.name)} — {r.url}", "info")


# --------------------------------------------------------------------------
# clean
# --------------------------------------------------------------------------
@app.command()
def clean(
    ctx: typer.Context,
    program: str = typer.Option(..., "--program", "-p", help="Workspace to clean."),
    state: bool = typer.Option(False, "--state", help="Reset stage state (forces a full re-run)."),
    cache: bool = typer.Option(False, "--cache", help="Clear the tool-output cache."),
    all_: bool = typer.Option(False, "--all", help="Both of the above."),
) -> None:
    """Reset stage state and/or clear cached tool output."""
    app_ctx = ctx.obj
    if all_:
        state = cache = True
    if not (state or cache):
        state = True  # sensible default
    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)
    if state:
        ws.state.reset()
        term.ok(f"reset stage state for '{program}'.")
    if cache:
        removed = app_ctx.cache.clear()
        term.ok(f"cleared {removed} cache entries.")


def run(argv: Optional[list[str]] = None) -> None:
    """Console-script / ``python -m huntkit`` entry point."""
    app(args=argv)


if __name__ == "__main__":  # pragma: no cover
    run()
