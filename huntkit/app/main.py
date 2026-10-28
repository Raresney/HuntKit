"""The HuntKit Typer application.

Defines the root command group, its global options, and the top-level
commands. Grouped commands (config/plugins/workspace) live in their own
modules and are mounted here. Run it with the ``huntkit`` console script or
``python -m huntkit`` — both resolve to :func:`run`.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from pathlib import Path
from typing import Optional

import typer
from rich.markup import escape

from .. import __version__
from ..ai import Advisor, ApprovalDenied, ProviderError, get_provider, provider_names
from ..core.workspace import Workspace, list_workspaces
from ..enrich import EnrichReport, run_enrich
from ..fingerprint import fingerprint_headers, has_waf
from ..history import DiffReport, capture, current_vs, find, latest, list_snapshots, save
from ..intel import IntelReport, Priority, save_report
from ..intel import analyze as run_analyze
from ..knowledge import Playbook, all_playbooks, get_playbook
from ..monitor import NOTIFY_CHANGES, NOTIFY_FINDINGS, MonitorResult, run_monitor
from ..pipeline import RECON_STAGES, ReconSummary, run_recon
from ..report import FORMATS, normalise_format
from ..report import build as report_build
from ..report import write as report_write
from ..scanner import ScanSummary, run_scan
from ..secrets import endpoints_from_paths, scan_paths
from ..shots import ShotSummary, run_shots
from ..tui import render_dashboard
from ..utils import filesystem as fs
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
        None,
        "--workspace",
        "-w",
        help="Workspace base dir (default ~/.huntkit).",
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
        term.warn(
            f"{missing}/{len(registry)} tools missing — those stages are skipped, "
            "HuntKit still runs."
        )
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
        ws,
        app_ctx.config,
        domain,
        stages=stages,
        resume=not fresh,
        runner=app_ctx.runner,
        registry=app_ctx.registry,
        on_event=_render_event,
        threads=threads,
        use_cache=not no_cache,
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
# scan
# --------------------------------------------------------------------------
def _render_scan_event(event: dict) -> None:
    kind = event.get("event")
    if kind == "scan_start":
        tools = ", ".join(event["tools"]) or "none installed"
        term.step(f"scanning {event['targets']} target(s) with: {tools}")
    elif kind == "plugin_done":
        term.bullet(f"{event['plugin']}: {event['found']} finding(s)", "ok")
    elif kind == "plugin_skip":
        term.bullet(f"{event['plugin']}: skipped ({event['reason']})", "muted")


@app.command()
def scan(
    ctx: typer.Context,
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Workspace to scan (default: the only one)."
    ),
    tool: Optional[list[str]] = typer.Option(
        None,
        "--tool",
        "-T",
        help="Restrict to these scanners (repeatable; default: all available).",
    ),
    threads: Optional[int] = typer.Option(
        None, "--threads", "-t", help="Concurrency (default: config general.threads)."
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Bypass the tool-output cache for this run."
    ),
) -> None:
    """Run the vuln/fuzz scanners (nuclei, dalfox, …) over the gathered URLs."""
    app_ctx = ctx.obj
    program = program or _pick_program(app_ctx, default="")
    if not program:
        term.error("which workspace? pass -p <program> (none, or several, found).")
        raise typer.Exit(2)

    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)
    term.banner(f"scan — {program}")
    summary = run_scan(
        ws,
        app_ctx.config,
        tools=tool,
        runner=app_ctx.runner,
        registry=app_ctx.registry,
        on_event=_render_scan_event,
        threads=threads,
        use_cache=not no_cache,
    )

    if summary.targets == 0:
        term.warn(f"no in-scope URLs to scan for '{program}'.")
        term.info(
            f"gather some first:  huntkit recon <domain> -p {program}  (the live & urls stages)"
        )
        raise typer.Exit(0)

    if not summary.ran:
        term.warn("no scanner ran — install one (e.g. nuclei) to enable this phase.")
        term.info("see what's available:  huntkit doctor")
        raise typer.Exit(0)

    _print_scan_summary(summary, ws)


def _print_scan_summary(summary: ScanSummary, ws: Workspace) -> None:
    rows = []
    for o in summary.outcomes:
        status = f"{o.count} finding(s)" if o.ran else f"[muted]skipped: {o.reason}[/muted]"
        rows.append((o.tool, status))
    term.print_table("Scan summary", ["scanner", "result"], rows)
    term.ok(
        f"{summary.total_findings} finding(s) across {summary.targets} target(s). "
        f"Details under {ws.path('scans')}"
    )
    if summary.total_findings:
        term.info(f"fold findings into host scoring:  huntkit analyze -p {summary.program}")


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
    term.info(
        "hosts by priority: "
        + "  ".join(
            f"[{p.style}]{p.label}[/{p.style}] {report.summary[p.label]}"
            for p in sorted(Priority, reverse=True)
            if report.summary[p.label]
        )
    )

    rows = []
    for h in report.hosts[:top]:
        pr = h.priority
        rows.append(
            (
                h.host,
                f"[{pr.style}]{pr.label}[/{pr.style}]",
                str(h.score),
                str(len(h.signals)),
                ", ".join(h.playbooks[:4]) or "-",
            )
        )
    term.print_table(
        "Prioritised hosts", ["host", "priority", "score", "signals", "playbooks"], rows
    )

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
        (
            f"[{s.severity.style}]{s.severity.label}[/{s.severity.style}]",
            s.host,
            s.title,
            s.evidence,
        )
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
        rows.append(
            (
                p.playbook,
                p.name,
                f"[{p.severity.style}]{p.severity.label}[/{p.severity.style}]",
                str(len(p.hosts)),
                where,
            )
        )
    term.print_table(
        "Attack paths (highest impact first)",
        ["id", "playbook", "severity", "hosts", "where"],
        rows,
    )
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
        term.info(
            "hosts by priority: "
            + "  ".join(
                f"[{p.style}]{p.label}[/{p.style}] {intel.summary[p.label]}"
                for p in sorted(Priority, reverse=True)
                if intel.summary[p.label]
            )
        )
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
    md: bool = typer.Option(False, "--md", help="Print raw Markdown (for reports / copy-paste)."),
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
# advise (AI)
# --------------------------------------------------------------------------
@app.command()
def advise(
    ctx: typer.Context,
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Workspace to advise on (default: the only one)."
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", help="ollama | claude | openai (default: config ai.provider)."
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m", help="Override the provider's default model."
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the cloud-send confirmation (for scripting)."
    ),
) -> None:
    """Ask a local or cloud LLM to prioritise the recon findings into a plan."""
    app_ctx = ctx.obj
    program = program or _pick_program(app_ctx, default="")
    if not program:
        term.error("which workspace? pass -p <program> (none, or several, found).")
        raise typer.Exit(2)

    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)
    report = run_analyze(ws)
    if not report.signals:
        term.warn(f"no findings to advise on for '{program}'.")
        term.info(
            f"gather & score first:  huntkit recon <domain> -p {program} && huntkit analyze -p {program}"
        )
        raise typer.Exit(0)

    name = (provider or app_ctx.config.ai.provider or "ollama").strip().lower()
    prov = get_provider(name)
    if prov is None:
        term.error(f"unknown AI provider: {name}")
        term.info("choose one:  " + ", ".join(provider_names()))
        raise typer.Exit(2)

    if not prov.available(app_ctx.config):
        term.error(f"provider '{name}' is not usable right now.")
        if prov.is_local:
            term.info(f"start it:  ollama serve   (endpoint {app_ctx.config.ai.endpoint})")
        else:
            term.info(f"set an API key:  export HUNTKIT_APIKEY_{name.upper()}=<key>")
        raise typer.Exit(1)

    advisor = Advisor(prov, app_ctx.config)
    model_id = advisor.resolve_model(model)
    term.banner(f"advise — {program}  ({name} / {model_id})")

    def _approve(payload: str) -> bool:
        return _confirm_cloud_send(name, prov.endpoint_host(app_ctx.config), model_id, payload, yes)

    try:
        advice = advisor.advise(report, model=model, approve=_approve)
    except ApprovalDenied:
        term.warn("aborted — nothing was sent off your machine.")
        raise typer.Exit(0) from None
    except ProviderError as e:
        term.error(str(e))
        raise typer.Exit(1) from None

    if advice.is_local:
        term.info(f"local provider — data stayed on {advice.endpoint}")
    term.step("Advisor")
    term.console.print(advice.answer, markup=False, highlight=False)


def _confirm_cloud_send(
    provider: str, host: str, model: str, payload: str, assume_yes: bool
) -> bool:
    """Show exactly what will leave the machine, then require a clear yes."""
    term.warn(f"'{provider}' is a CLOUD model — this sends your recon data to {host}.")
    term.info(f"model: {model}   destination: {host}")
    term.console.rule("exact text that will be sent")
    term.console.print(payload, markup=False, highlight=False)
    term.console.rule()
    if assume_yes:
        term.info("--yes supplied — sending without a prompt.")
        return True
    return typer.confirm("Send this recon data to the cloud provider?", default=False)


# --------------------------------------------------------------------------
# secrets
# --------------------------------------------------------------------------
@app.command()
def secrets(
    paths: list[Path] = typer.Argument(..., help="Files or directories to scan for leaks."),
    endpoints: bool = typer.Option(
        False, "--endpoints", "-e", help="Also extract JS endpoints/paths."
    ),
    out: Optional[Path] = typer.Option(
        None, "--out", "-o", help="Write findings (redacted) as JSON here."
    ),
    top: int = typer.Option(50, "--top", "-n", help="Max rows to print."),
) -> None:
    """Scan gathered text (JS, configs, dumps) for leaked secrets and endpoints."""
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        term.error("not found: " + ", ".join(missing))
        raise typer.Exit(2)

    hits = scan_paths(paths)
    hits.sort(key=lambda h: (-int(h.severity), h.source, h.line))

    term.banner("secrets scan")
    if hits:
        rows = [
            (
                f"[{h.severity.style}]{h.severity.label}[/{h.severity.style}]",
                h.title,
                f"{h.source}:{h.line}",
                h.match,
            )
            for h in hits[:top]
        ]
        term.print_table(
            "Potential secrets (redacted)", ["severity", "type", "where", "match"], rows
        )
        term.warn(
            f"{len(hits)} potential secret(s) — verify before reporting; values are redacted."
        )
    else:
        term.ok("no secrets matched.")

    eps: list[str] = []
    if endpoints:
        eps = endpoints_from_paths(paths)
        if eps:
            term.step(f"JS endpoints ({len(eps)})")
            for ep in eps[:top]:
                term.bullet(escape(ep), "info")
        else:
            term.info("no endpoints extracted.")

    if out:
        payload = {"secrets": [h.to_dict() for h in hits], "endpoints": eps}
        fs.write_text(out, json.dumps(payload, indent=2))
        term.ok(f"wrote {out}")


# --------------------------------------------------------------------------
# fingerprint
# --------------------------------------------------------------------------
@app.command()
def fingerprint(
    source: str = typer.Argument(
        "-", help="Header file, or - for stdin (e.g. curl -sI URL | huntkit fingerprint)."
    ),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write matches as JSON here."),
) -> None:
    """Identify CDN / WAF / cloud / tech from captured HTTP response headers."""
    if source == "-":
        text = sys.stdin.read()
    else:
        path = Path(source)
        if not path.exists():
            term.error(f"not found: {source}")
            raise typer.Exit(2)
        text = path.read_text(encoding="utf-8", errors="ignore")

    matches = fingerprint_headers(text)
    term.banner("fingerprint")
    if not matches:
        term.warn("no CDN/WAF/cloud/tech fingerprints matched.")
        term.info("feed response headers, e.g.:  curl -sI https://target | huntkit fingerprint")
        raise typer.Exit(0)

    rows = [
        (f"[{m.severity.style}]{m.kind}[/{m.severity.style}]", m.name, escape(m.evidence))
        for m in matches
    ]
    term.print_table("Fingerprints", ["kind", "vendor", "evidence"], rows)
    if has_waf(matches):
        wafs = ", ".join(m.name for m in matches if m.kind == "waf")
        term.warn(
            f"WAF present ({wafs}) — expect filtering; tune payloads/rate and "
            "consider origin-IP discovery."
        )
    if out:
        fs.write_text(out, json.dumps([m.to_dict() for m in matches], indent=2))
        term.ok(f"wrote {out}")


# --------------------------------------------------------------------------
# enrich
# --------------------------------------------------------------------------
def _render_enrich_event(event: dict) -> None:
    kind = event.get("event")
    if kind == "favicon_start":
        term.step(f"favicon: hashing {event['targets']} origin(s)")
    elif kind == "favicon_done":
        term.bullet(f"favicon: {event['hits']} hash(es)", "ok")
    elif kind == "asn_start":
        term.step(f"asn: resolving {event['targets']} host(s) via Team Cymru WHOIS")
    elif kind == "asn_done":
        term.bullet(f"asn: {event['hits']} mapping(s)", "ok")


@app.command()
def enrich(
    ctx: typer.Context,
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Workspace to enrich (default: the only one)."
    ),
    favicon: bool = typer.Option(True, "--favicon/--no-favicon", help="Hash site favicons."),
    asn: bool = typer.Option(True, "--asn/--no-asn", help="Look up ASN / BGP prefix per host."),
    threads: int = typer.Option(10, "--threads", "-t", help="Concurrency."),
    out: Optional[Path] = typer.Option(
        None, "--out", "-o", help="Also write the report JSON here."
    ),
) -> None:
    """Add favicon hashes (Shodan pivot) and ASN/BGP origins to the recon surface."""
    app_ctx = ctx.obj
    program = program or _pick_program(app_ctx, default="")
    if not program:
        term.error("which workspace? pass -p <program> (none, or several, found).")
        raise typer.Exit(2)
    if not (favicon or asn):
        term.error("nothing to do — enable at least one of --favicon / --asn.")
        raise typer.Exit(2)

    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)
    term.banner(f"enrich — {program}")
    if asn:
        term.info(
            "note: ASN lookup sends each in-scope host's resolved IP to "
            "whois.cymru.com (public third-party WHOIS)."
        )
    report = run_enrich(
        ws, do_favicon=favicon, do_asn=asn, threads=threads, on_event=_render_enrich_event
    )
    _print_enrich(report, ws, out)


def _print_enrich(report: EnrichReport, ws: Workspace, out: Optional[Path]) -> None:
    favs = [f for f in report.favicons if f.ok]
    if favs:
        rows = [(escape(f.url), str(f.hash), f.shodan) for f in favs]
        term.print_table("Favicon hashes", ["origin", "mmh3", "shodan pivot"], rows)
    asns = [a for a in report.asns if a.ok]
    if asns:
        arows = [(escape(a.host), a.ip, f"AS{a.asn}", a.prefix, escape(a.as_name)) for a in asns]
        term.print_table("ASN origins", ["host", "ip", "asn", "prefix", "network"], arows)
        if report.unique_asns:
            term.info(
                f"{len(report.unique_asns)} unique ASN(s) to sweep: "
                + ", ".join(f"AS{a}" for a in report.unique_asns)
            )

    if not favs and not asns:
        term.warn("no enrichment results — thin recon surface, or hosts unreachable.")
        term.info(f"gather some first:  huntkit recon <domain> -p {report.program}")

    term.ok(
        f"favicon: {report.favicon_hits}, asn: {report.asn_hits}. "
        f"Report: {ws.path('scans', 'enrich.json')}"
    )
    if out:
        fs.write_text(out, Path(ws.path("scans", "enrich.json")).read_text(encoding="utf-8"))
        term.ok(f"wrote {out}")


# --------------------------------------------------------------------------
# shots (screenshots)
# --------------------------------------------------------------------------
def _render_shots_event(event: dict) -> None:
    kind = event.get("event")
    if kind == "shots_start":
        term.step(f"capturing {event['targets']} URL(s) with gowitness")
    elif kind == "shots_done":
        term.bullet(f"captured {event['captured']} screenshot(s)", "ok")
    elif kind == "shots_error":
        term.bullet(f"capture failed: {event['reason']}", "muted")


@app.command()
def shots(
    ctx: typer.Context,
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Workspace to screenshot (default: the only one)."
    ),
) -> None:
    """Screenshot every live in-scope URL (gowitness) for the report gallery."""
    app_ctx = ctx.obj
    program = program or _pick_program(app_ctx, default="")
    if not program:
        term.error("which workspace? pass -p <program> (none, or several, found).")
        raise typer.Exit(2)

    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)
    term.banner(f"shots — {program}")
    summary = run_shots(ws, app_ctx.config, runner=app_ctx.runner, on_event=_render_shots_event)
    _print_shots_summary(summary, ws)


def _print_shots_summary(summary: ShotSummary, ws: Workspace) -> None:
    if summary.targets == 0:
        term.warn(f"no in-scope URLs to screenshot for '{summary.program}'.")
        term.info(f"gather some first:  huntkit recon <domain> -p {summary.program}")
        raise typer.Exit(0)
    if summary.captured == 0:
        term.warn("no screenshots captured — is gowitness installed?  huntkit doctor")
        raise typer.Exit(0)
    term.ok(f"{summary.captured}/{summary.targets} captured under {ws.path('reports', 'shots')}.")
    term.info(f"embed them in a gallery:  huntkit report -p {summary.program} -f html")


# --------------------------------------------------------------------------
# diff (snapshots over time)
# --------------------------------------------------------------------------
@app.command()
def diff(
    ctx: typer.Context,
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Workspace to diff (default: the only one)."
    ),
    save_baseline: bool = typer.Option(
        False, "--save", help="After diffing, save the current state as a new baseline."
    ),
    against: Optional[str] = typer.Option(
        None, "--against", help="Baseline snapshot id (default: the most recent)."
    ),
    show_list: bool = typer.Option(False, "--list", help="List saved snapshots and exit."),
    top: int = typer.Option(25, "--top", "-n", help="Max items to list per category."),
) -> None:
    """Show what changed since a saved snapshot — new subdomains, URLs, findings."""
    app_ctx = ctx.obj
    program = program or _pick_program(app_ctx, default="")
    if not program:
        term.error("which workspace? pass -p <program> (none, or several, found).")
        raise typer.Exit(2)
    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)

    if show_list:
        _print_snapshots(ws, program)
        raise typer.Exit(0)

    baseline = find(ws, against) if against else latest(ws)
    if against and baseline is None:
        term.error(f"no snapshot '{against}' — see them with:  huntkit diff -p {program} --list")
        raise typer.Exit(2)

    term.banner(f"diff — {program}")
    if baseline is None:
        if save_baseline:
            snap = save(ws, capture(ws))
            term.ok(f"no baseline yet — saved the current state as '{snap.stem}'.")
        else:
            term.warn("no baseline snapshot yet.")
            term.info(f"set one:  huntkit diff -p {program} --save")
        raise typer.Exit(0)

    report, now = current_vs(ws, baseline)
    _print_diff(report, top)
    if save_baseline:
        save(ws, now)
        term.ok(f"baseline updated → '{now.id}'.")


def _print_snapshots(ws: Workspace, program: str) -> None:
    snaps = list_snapshots(ws)
    term.banner(f"snapshots — {program}")
    if not snaps:
        term.warn("no snapshots saved yet.")
        term.info(f"save one:  huntkit diff -p {program} --save")
        return
    rows = [
        (s.id, s.generated, str(s.counts["live"]), str(s.counts["urls"]), str(s.counts["findings"]))
        for s in snaps
    ]
    term.print_table("Saved snapshots", ["id", "generated", "live", "urls", "findings"], rows)


def _print_diff(report: DiffReport, top: int) -> None:
    term.info(f"baseline '{report.base_id}' → now:  +{report.total_added}  -{report.total_removed}")
    if not report.has_changes:
        term.ok(f"no changes since '{report.base_id}'.")
        return

    rows = [(c.name, f"+{len(c.added)}", f"-{len(c.removed)}") for c in report.changed]
    term.print_table("Changed", ["category", "added", "removed"], rows)

    if report.new_findings:
        term.step(f"NEW findings ({len(report.new_findings)})")
        for item in report.new_findings[:top]:
            term.bullet(escape(item), "ok")

    for c in report.changed:
        if c.name == "findings" or not (c.added or c.removed):
            continue
        term.step(c.name)
        for item in c.added[:top]:
            term.bullet(f"+ {escape(item)}", "ok")
        for item in c.removed[:top]:
            term.bullet(f"- {escape(item)}", "muted")


# --------------------------------------------------------------------------
# dashboard (TUI)
# --------------------------------------------------------------------------
@app.command()
def dashboard(
    ctx: typer.Context,
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Workspace to show (default: the only one)."
    ),
    top: int = typer.Option(10, "--top", "-n", help="Rows per table."),
    watch: Optional[float] = typer.Option(
        None, "--watch", "-W", help="Redraw every N seconds (Ctrl-C to stop)."
    ),
) -> None:
    """Paint a one-screen engagement dashboard (optionally live with --watch)."""
    app_ctx = ctx.obj
    program = program or _pick_program(app_ctx, default="")
    if not program:
        term.error("which workspace? pass -p <program> (none, or several, found).")
        raise typer.Exit(2)
    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)

    if watch and watch > 0:
        _watch_dashboard(ws, top, watch)
        return
    term.console.print(render_dashboard(ws, top=top))


def _watch_dashboard(ws: Workspace, top: int, interval: float) -> None:  # pragma: no cover
    import time

    from rich.live import Live

    try:
        with Live(render_dashboard(ws, top=top), console=term.console, screen=True) as live:
            while True:
                time.sleep(interval)
                live.update(render_dashboard(ws, top=top))
    except KeyboardInterrupt:
        term.info("stopped.")


# --------------------------------------------------------------------------
# monitor (continuous re-sweep + webhook)
# --------------------------------------------------------------------------
def _render_monitor_event(event: dict) -> None:
    kind = event.get("event")
    if kind == "monitor_start":
        base = event.get("baseline") or "none"
        term.step(f"monitor {event['program']}  (baseline: {base})")
    elif kind == "recon_begin":
        term.bullet("re-running recon…", "muted")
    elif kind == "notify":
        host = urllib.parse.urlsplit(event["webhook"]).hostname or "?"
        term.warn(f"egress: sending the delta to webhook host '{host}'")


@app.command()
def monitor(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="Seed domain to re-sweep."),
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Workspace to use (default: the domain)."
    ),
    webhook: Optional[str] = typer.Option(
        None,
        "--webhook",
        "-u",
        help="Slack/Discord incoming webhook; receives the delta (opt-in egress).",
    ),
    notify_on: str = typer.Option(
        NOTIFY_FINDINGS, "--notify-on", help="findings | changes — what fires the webhook."
    ),
    interval: Optional[float] = typer.Option(
        None, "--interval", "-i", help="Re-sweep every N minutes (Ctrl-C to stop)."
    ),
) -> None:
    """Re-sweep a program, diff against the last snapshot, notify on new findings."""
    app_ctx = ctx.obj
    try:
        domain = v.normalise_domain(domain)
    except v.ValidationError:
        term.error(f"not a valid domain: {domain}")
        raise typer.Exit(2) from None

    if notify_on not in (NOTIFY_FINDINGS, NOTIFY_CHANGES):
        term.error(f"--notify-on must be '{NOTIFY_FINDINGS}' or '{NOTIFY_CHANGES}'.")
        raise typer.Exit(2)

    program = program or _pick_program(app_ctx, default=domain)
    ws = Workspace.open(program, config=app_ctx.config, base=app_ctx.base)

    # monitor re-runs recon, so honour scope exactly as `recon` does.
    if ws.has_scope():
        if not ws.in_scope(domain):
            term.error(f"{domain} is out of scope for '{program}'.")
            term.info(f"add it:  huntkit init {program} -s {domain}")
            raise typer.Exit(2)
    else:
        ws.set_scope([f"*.{domain}"], [])
        term.warn(f"no scope set — limiting to *.{domain}. Refine with `huntkit init`.")

    def _recon() -> ReconSummary:
        return run_recon(
            ws,
            app_ctx.config,
            domain,
            runner=app_ctx.runner,
            registry=app_ctx.registry,
            on_event=_render_event,
        )

    def _sweep() -> MonitorResult:
        return run_monitor(
            ws,
            app_ctx.config,
            domain,
            webhook=webhook,
            notify_on=notify_on,
            recon=_recon,
            on_event=_render_monitor_event,
        )

    if interval and interval > 0:
        _watch_monitor(_sweep, interval)
        return
    term.banner(f"monitor {domain}  ->  {program}")
    _print_monitor(_sweep())


def _print_monitor(result: MonitorResult) -> None:
    if result.first_run or result.report is None:
        term.ok(
            f"first run — saved baseline '{result.snapshot.id}'. Re-run later to see the delta."
        )
        return
    _print_diff(result.report, top=25)
    if result.notified:
        term.ok("webhook notified.")
    elif result.report.has_changes:
        term.info("changes found; no webhook set (pass --webhook to get pinged).")


def _watch_monitor(sweep, interval_minutes: float) -> None:  # pragma: no cover
    import time

    try:
        while True:
            _print_monitor(sweep())
            term.info(f"next sweep in {interval_minutes} min (Ctrl-C to stop)…")
            time.sleep(interval_minutes * 60)
    except KeyboardInterrupt:
        term.info("stopped.")


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
