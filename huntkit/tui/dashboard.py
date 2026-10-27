"""A one-screen engagement dashboard, composed from what a workspace holds.

`huntkit dashboard -p <prog>` paints the whole picture on a single screen —
priority breakdown, recon surface, the top scored hosts and attack paths, the
notable exposures, enrichment highlights, and when the surface last changed.
With ``--watch`` it redraws on an interval, so a long recon in one terminal can
be watched live in another.

Built entirely on Rich (already a runtime dependency) — no TUI framework is
added. :func:`render_dashboard` is a pure function returning a Rich renderable,
so it is unit-tested by rendering to a recording console, and the live loop
stays a thin wrapper around it.
"""

from __future__ import annotations

import json

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.workspace import Workspace
from ..history import latest
from ..intel import Priority
from ..report import build as report_build
from ..report.builder import Report
from ..utils.severity import Severity

_ENRICH_JSON = "scans/enrich.json"


def _header(report: Report) -> Panel:
    body = Text()
    body.append(report.program, style="bold cyan")
    scope = ", ".join(report.scope_in) or "—"
    body.append(f"\nin scope: {scope}", style="dim")
    if report.scope_out:
        body.append(f"\nout of scope: {', '.join(report.scope_out)}", style="dim")
    return Panel(body, title="HuntKit", title_align="left", box=box.ROUNDED)


def _priority_bar(report: Report) -> Panel:
    t = Table.grid(expand=True, padding=(0, 2))
    labels = [p.label for p in sorted(Priority, reverse=True)]
    for _ in labels:
        t.add_column(justify="center", ratio=1)
    counts = report.intel.summary
    t.add_row(*[Text(str(counts.get(lbl, 0)), style=f"bold {lbl}") for lbl in labels])
    t.add_row(*[Text(lbl, style="dim") for lbl in labels])
    sig = len(report.intel.signals)
    hosts = len(report.intel.hosts)
    return Panel(t, title=f"priority · {sig} signals / {hosts} hosts", title_align="left")


def _recon_bar(report: Report) -> Panel:
    t = Table.grid(expand=True, padding=(0, 2))
    items = list(report.recon.items())
    for _ in items:
        t.add_column(justify="center", ratio=1)
    t.add_row(*[Text(str(n), style="bold") for _, n in items])
    t.add_row(*[Text(label, style="dim") for label, _ in items])
    return Panel(t, title="recon surface", title_align="left")


def _hosts_table(report: Report, top: int) -> Table:
    t = Table(title="top hosts", title_justify="left", box=box.SIMPLE, expand=True)
    t.add_column("host", overflow="fold")
    t.add_column("pri")
    t.add_column("score", justify="right")
    t.add_column("sig", justify="right")
    t.add_column("playbooks", overflow="fold")
    for h in report.intel.hosts[:top]:
        t.add_row(
            h.host,
            Text(h.priority.label, style=h.priority.style),
            str(h.score),
            str(len(h.signals)),
            ", ".join(h.playbooks[:3]) or "—",
        )
    return t


def _paths_table(report: Report, top: int) -> Table:
    t = Table(title="attack paths", title_justify="left", box=box.SIMPLE, expand=True)
    t.add_column("playbook", overflow="fold")
    t.add_column("sev")
    t.add_column("hosts", justify="right")
    for p in report.intel.attack_paths()[:top]:
        t.add_row(p.name, Text(p.severity.label, style=p.severity.style), str(len(p.hosts)))
    return t


def _notable_table(report: Report, top: int) -> Table:
    t = Table(title="notable exposures", title_justify="left", box=box.SIMPLE, expand=True)
    t.add_column("sev")
    t.add_column("host", overflow="fold")
    t.add_column("finding", overflow="fold")
    hot = sorted(
        (s for s in report.intel.signals if int(s.severity) >= Severity.HIGH),
        key=lambda s: (-int(s.severity), s.host),
    )
    for s in hot[:top]:
        t.add_row(Text(s.severity.label, style=s.severity.style), s.host, s.title)
    return t


def _enrich_panel(ws: Workspace) -> Panel | None:
    path = ws.path(_ENRICH_JSON)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    favs = [f for f in data.get("favicons", []) if f.get("hash") is not None]
    asns = [a for a in data.get("asns", []) if a.get("asn")]
    if not favs and not asns:
        return None
    body = Text()
    body.append(f"favicons hashed: {len(favs)}\n", style="bold")
    unique_asns = sorted({a["asn"] for a in asns}, key=lambda s: int(s)) if asns else []
    body.append(f"ASNs: {len(asns)} host(s) across {len(unique_asns)} network(s)", style="bold")
    if unique_asns:
        body.append("  " + ", ".join(f"AS{a}" for a in unique_asns[:8]), style="dim")
    return Panel(body, title="enrichment", title_align="left")


def _snapshot_line(ws: Workspace) -> Text:
    snap = latest(ws)
    if snap is None:
        return Text("no snapshot yet — `huntkit diff --save` to set a baseline", style="dim")
    return Text(
        f"last snapshot {snap.id} · live {snap.counts['live']} · "
        f"urls {snap.counts['urls']} · findings {snap.counts['findings']}",
        style="dim",
    )


def render_dashboard(ws: Workspace, *, top: int = 10) -> RenderableType:
    """Compose the one-screen dashboard for a workspace (pure; no I/O beyond reads)."""
    report = report_build(ws)
    parts: list[RenderableType] = [
        _header(report),
        _priority_bar(report),
        _recon_bar(report),
    ]
    if report.intel.hosts:
        parts.append(_hosts_table(report, top))
    if report.intel.attack_paths():
        parts.append(_paths_table(report, top))
    if any(int(s.severity) >= Severity.HIGH for s in report.intel.signals):
        parts.append(_notable_table(report, top))
    enrich = _enrich_panel(ws)
    if enrich is not None:
        parts.append(enrich)
    parts.append(_snapshot_line(ws))
    return Group(*parts)
