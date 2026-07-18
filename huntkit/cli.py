"""HuntKit command-line interface.

    huntkit doctor                 # what's installed / missing
    huntkit init <program> -d dom  # create a workspace + set scope
    huntkit recon <domain>         # full recon chain
    huntkit scan                   # nuclei + optional fuzz on findings
    huntkit ideas [category]       # context-aware suggestions / playbooks
    huntkit advise                 # local-LLM next steps (Ollama, optional)
    huntkit status                 # what has run in this workspace
    huntkit report                 # write a markdown report
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, advisor, methodology, recon, report, scan, tools, ui
from .workspace import Workspace, home, list_workspaces


def _ws(args) -> Workspace:
    base = Path(args.workspace).expanduser() if getattr(args, "workspace", None) else None
    program = getattr(args, "program", None) or _default_program()
    if program is None:
        ui.error("no program selected. Use `huntkit init <program>` or pass -p <program>.")
        sys.exit(2)
    return Workspace.open(program, base)


def _default_program() -> str | None:
    """If exactly one workspace exists, use it; else require -p."""
    existing = list_workspaces()
    if len(existing) == 1:
        return existing[0]
    return None


# ---- command handlers ----------------------------------------------------
def cmd_doctor(args) -> int:
    ui.banner("HuntKit doctor — toolchain check")
    rows = []
    missing = 0
    for tool in tools.REGISTRY.values():
        status = "OK" if tool.installed else "MISSING"
        if not tool.installed:
            missing += 1
        rows.append((tool.name, tool.category, status,
                     tool.path or tool.install))
    ui.table("", ["tool", "category", "status", "path / install"], rows)
    if missing:
        ui.warn(f"{missing} tool(s) missing. HuntKit still runs; those stages are skipped.")
    else:
        ui.ok("full toolchain present.")
    ui.info(f"workspaces stored under: {home()}")
    return 0


def cmd_init(args) -> int:
    ws = Workspace.open(args.program, Path(args.workspace).expanduser() if args.workspace else None)
    in_scope = args.domain or []
    out_scope = args.out_of_scope or []
    if in_scope or out_scope:
        ws.set_scope(in_scope, out_scope)
    ws.record_run("init", args.program)
    ui.ok(f"workspace ready: {ws.root}")
    if in_scope:
        ui.info(f"in-scope: {', '.join(in_scope)}")
    ui.info(f"next:  huntkit recon {in_scope[0] if in_scope else '<domain>'} -p {args.program}")
    return 0


def cmd_recon(args) -> int:
    ws = _ws(args)
    if not ws.in_scope(args.domain):
        ui.error(f"{args.domain} is not in scope for '{ws.program}'. "
                 f"Add it:  huntkit init {ws.program} -d {args.domain}")
        return 2
    if args.stage == "all":
        recon.full(ws, args.domain)
    elif args.stage == "subs":
        recon.enum_subdomains(ws, args.domain)
    elif args.stage == "live":
        recon.probe_live(ws)
    elif args.stage == "ports":
        recon.scan_ports(ws)
    elif args.stage == "urls":
        recon.gather_urls(ws, args.domain)
    return 0


def cmd_scan(args) -> int:
    ws = _ws(args)
    if args.type in ("all", "nuclei"):
        scan.nuclei_scan(ws, severity=args.severity)
    if args.type in ("all", "xss"):
        scan.xss_scan(ws)
    if args.type == "dir":
        if not args.target:
            ui.error("dir scan needs --target <url>")
            return 2
        scan.dir_fuzz(ws, args.target, wordlist=args.wordlist, extensions=args.extensions)
    if args.type == "params":
        if not args.target:
            ui.error("params scan needs --target <url>")
            return 2
        scan.find_params(ws, args.target)
    return 0


def cmd_ideas(args) -> int:
    if args.category == "list":
        methodology.list_playbooks()
        return 0
    if args.category:
        return 0 if methodology.show_playbook(args.category) else 2
    # no category -> context-aware suggestions from the workspace
    ws = _ws(args)
    methodology.suggest(ws)
    return 0


def cmd_advise(args) -> int:
    ws = _ws(args)
    advisor.advise(ws, model=args.model)
    return 0


def cmd_status(args) -> int:
    existing = list_workspaces()
    if not existing:
        ui.warn("no workspaces yet. Start with:  huntkit init <program> -d <domain>")
        return 0
    if not getattr(args, "program", None) and len(existing) > 1:
        ui.banner("HuntKit workspaces")
        for name in existing:
            ui.bullet(name)
        ui.info("Detail:  huntkit status -p <program>")
        return 0
    ws = _ws(args)
    ui.banner(f"HuntKit status — {ws.program}")
    counts = ws.state.get("counts", {})
    ui.table("Counts", ["metric", "count"],
             [(k, str(v)) for k, v in counts.items()] or [("(none)", "0")])
    runs = ws.state.get("runs", [])
    if runs:
        ui.step("Recent activity")
        for run in runs[-12:]:
            detail = f" — {run['detail']}" if run.get("detail") else ""
            ui.bullet(f"{run['when']}  {run['action']}{detail}")
    ui.info(f"files: {ws.root}")
    return 0


def cmd_report(args) -> int:
    ws = _ws(args)
    report.write(ws)
    return 0


# ---- parser --------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="huntkit",
        description="Local bug bounty recon & methodology copilot.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version", version=f"HuntKit {__version__}")
    p.add_argument("-w", "--workspace", help="workspace base dir (default ~/.huntkit)")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("doctor", help="check installed tools")
    sp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("init", help="create a program workspace")
    sp.add_argument("program")
    sp.add_argument("-d", "--domain", action="append", help="in-scope domain (repeatable)")
    sp.add_argument("-x", "--out-of-scope", action="append", help="out-of-scope pattern")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("recon", help="run recon stages")
    sp.add_argument("domain")
    sp.add_argument("-p", "--program", help="workspace (default: the only one, if unique)")
    sp.add_argument("-s", "--stage", choices=["all", "subs", "live", "ports", "urls"],
                    default="all")
    sp.set_defaults(func=cmd_recon)

    sp = sub.add_parser("scan", help="vuln / fuzz scanning")
    sp.add_argument("-p", "--program")
    sp.add_argument("-t", "--type", choices=["all", "nuclei", "xss", "dir", "params"],
                    default="all")
    sp.add_argument("--target", help="url for dir/params scans")
    sp.add_argument("--severity", default="low,medium,high,critical")
    sp.add_argument("--wordlist", help="wordlist for dir fuzzing")
    sp.add_argument("--extensions", help="ffuf extensions, e.g. .php,.bak")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("ideas", help="playbooks + context-aware suggestions")
    sp.add_argument("category", nargs="?",
                    help="bug class (idor/xss/ssrf/...), 'list', or empty for auto-suggest")
    sp.add_argument("-p", "--program")
    sp.set_defaults(func=cmd_ideas)

    sp = sub.add_parser("advise", help="local-LLM next steps (Ollama, optional)")
    sp.add_argument("-p", "--program")
    sp.add_argument("-m", "--model", default="llama3.2")
    sp.set_defaults(func=cmd_advise)

    sp = sub.add_parser("status", help="workspace status")
    sp.add_argument("-p", "--program")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("report", help="write markdown report")
    sp.add_argument("-p", "--program")
    sp.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        ui.warn("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
