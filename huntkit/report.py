"""Markdown report generation from a workspace."""

from __future__ import annotations

import time

from . import ui
from .workspace import Workspace


def build(ws: Workspace) -> str:
    counts = ws.state.get("counts", {})
    scope = ws.state.get("scope", {})
    lines: list[str] = []
    add = lines.append

    add(f"# Recon report — {ws.program}")
    add("")
    add(f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S')} by HuntKit_")
    add("")

    add("## Scope")
    add("")
    add("**In scope:**")
    for s in scope.get("in", []) or ["_unspecified_"]:
        add(f"- {s}")
    if scope.get("out"):
        add("")
        add("**Out of scope:**")
        for s in scope["out"]:
            add(f"- {s}")
    add("")

    add("## Summary")
    add("")
    add("| Metric | Count |")
    add("| --- | --- |")
    for key in ("subdomains", "live", "urls", "nuclei_findings"):
        if key in counts:
            add(f"| {key.replace('_', ' ')} | {counts[key]} |")
    add("")

    findings = ws.read_lines("scans/nuclei.txt")
    if findings:
        add("## nuclei findings")
        add("")
        for f in findings:
            add(f"- `{f}`")
        add("")

    live = ws.read_lines("recon/live.txt")
    if live:
        add(f"## Live hosts ({len(live)})")
        add("")
        add("```")
        lines.extend(live[:200])
        if len(live) > 200:
            add(f"... {len(live) - 200} more (see recon/live.txt)")
        add("```")
        add("")

    params = ws.read_lines("urls/params.txt")
    if params:
        add(f"## Parameterised URLs ({len(params)})")
        add("")
        add("```")
        lines.extend(params[:100])
        if len(params) > 100:
            add(f"... {len(params) - 100} more (see urls/params.txt)")
        add("```")
        add("")

    add("## Activity log")
    add("")
    for run in ws.state.get("runs", [])[-30:]:
        detail = f" — {run['detail']}" if run.get("detail") else ""
        add(f"- `{run['when']}` **{run['action']}**{detail}")
    add("")

    return "\n".join(lines)


def write(ws: Workspace) -> None:
    md = build(ws)
    out = ws.path("reports", f"report_{time.strftime('%Y%m%d_%H%M%S')}.md")
    out.write_text(md, encoding="utf-8")
    latest = ws.path("reports", "latest.md")
    latest.write_text(md, encoding="utf-8")
    ws.record_run("report", str(out.name))
    ui.ok(f"report written -> {out}")
    ui.info(f"latest symlinked copy -> {latest}")
