"""Intelligence engine — recon output -> scored, prioritised attack surface.

Reads a workspace's recon artifacts, runs them through the signal catalog,
groups the findings per host, scores each host Low -> Critical, and rolls the
signals up into prioritised **attack paths** (which bug-class playbook to run,
and where). Pure analysis over data already on disk — it never touches the
target.

The layout paths it reads mirror :data:`huntkit.pipeline.STAGE_FILES`; they are
duplicated here as small constants so the intelligence layer stays independent
of the pipeline (and trivially testable without the plugin registry).
"""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

from ..core.workspace import Workspace
from ..knowledge.playbooks import titles as _playbook_titles
from ..utils import filesystem as fs
from .signals import Severity, Signal, scan_signals, url_host

# Workspace-relative recon artifacts the engine consumes.
_LIVE = "recon/live.txt"
_URLS = "urls/urls.txt"
_PORTS = "recon/ports.txt"
_SUBS = "recon/subdomains.txt"
_RESOLVED = "recon/resolved.txt"

# Human names for the bug-class playbook ids. The knowledge base owns the
# playbook catalog, so names come from there — one source of truth, and an
# attack path in a report links straight to `huntkit playbook <id>`.
PLAYBOOK_NAMES: dict[str, str] = _playbook_titles()


class Priority(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def style(self) -> str:  # matches the theme keys in utils.terminal
        return self.name.lower()


def _priority(signals: list[Signal]) -> Priority:
    """Host priority = worst single signal, nudged up by breadth of surface.

    A Critical signal makes the host Critical outright; otherwise a High
    signal (or enough stacked medium/low ones) makes it High, and so on. The
    aggregate thresholds mean a host with many medium issues still rises.
    """
    if not signals:
        return Priority.LOW
    top = max(s.severity for s in signals)
    total = sum(int(s.severity) for s in signals)
    if top >= Severity.CRITICAL:
        return Priority.CRITICAL
    if top >= Severity.HIGH or total >= 8:
        return Priority.HIGH
    if top >= Severity.MEDIUM or total >= 4:
        return Priority.MEDIUM
    return Priority.LOW


@dataclass
class HostIntel:
    host: str
    signals: list[Signal]

    @property
    def score(self) -> int:
        return sum(int(s.severity) for s in self.signals)

    @property
    def priority(self) -> Priority:
        return _priority(self.signals)

    @property
    def playbooks(self) -> list[str]:
        """Suggested playbooks, most-severe signal first, de-duplicated."""
        ordered: list[str] = []
        for s in sorted(self.signals, key=lambda x: -int(x.severity)):
            for pb in s.playbooks:
                if pb not in ordered:
                    ordered.append(pb)
        return ordered

    def ranked_signals(self) -> list[Signal]:
        return sorted(self.signals, key=lambda s: (-int(s.severity), s.category, s.id))

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "priority": self.priority.label,
            "score": self.score,
            "playbooks": self.playbooks,
            "signals": [s.to_dict() for s in self.ranked_signals()],
        }


@dataclass
class AttackPath:
    """One bug-class playbook and everywhere the recon points it."""

    playbook: str
    name: str
    severity: Severity          # worst contributing signal
    hosts: list[str]
    signals: list[Signal]

    def to_dict(self) -> dict:
        return {
            "playbook": self.playbook,
            "name": self.name,
            "severity": self.severity.label,
            "hosts": self.hosts,
            "signal_count": len(self.signals),
        }


@dataclass
class IntelReport:
    program: str
    hosts: list[HostIntel]
    generated: float = field(default_factory=time.time)

    @property
    def signals(self) -> list[Signal]:
        return [s for h in self.hosts for s in h.signals]

    @property
    def summary(self) -> dict[str, int]:
        """Host counts per priority, always highest-first and fully populated."""
        counts = Counter(h.priority for h in self.hosts)
        return {p.label: counts.get(p, 0) for p in sorted(Priority, reverse=True)}

    def attack_paths(self) -> list[AttackPath]:
        groups: dict[str, list[Signal]] = defaultdict(list)
        for s in self.signals:
            for pb in s.playbooks:
                groups[pb].append(s)
        paths = [
            AttackPath(
                playbook=pb,
                name=PLAYBOOK_NAMES.get(pb, pb),
                severity=max(s.severity for s in sigs),
                hosts=sorted({s.host for s in sigs}),
                signals=sigs,
            )
            for pb, sigs in groups.items()
        ]
        paths.sort(key=lambda p: (-int(p.severity), -len(p.hosts), p.playbook))
        return paths

    def to_dict(self) -> dict:
        return {
            "program": self.program,
            "generated": self.generated,
            "summary": self.summary,
            "hosts": [h.to_dict() for h in self.hosts],
            "attack_paths": [p.to_dict() for p in self.attack_paths()],
        }


def _host_pool(ws: Workspace, live: list[str]) -> list[str]:
    """Every hostname worth label-analysis: subdomains, resolved, live hosts."""
    pool: set[str] = set(ws.read_lines(_SUBS)) | set(ws.read_lines(_RESOLVED))
    for url in live:
        host = url_host(url)
        if host:
            pool.add(host)
    return sorted(h.lower() for h in pool if h.strip())


def analyze(ws: Workspace) -> IntelReport:
    """Score a workspace's recon surface into a prioritised intel report."""
    live = ws.read_lines(_LIVE)
    urls = ws.read_lines(_URLS)
    ports = ws.read_lines(_PORTS)
    hosts = _host_pool(ws, live)
    url_pool = list(dict.fromkeys(live + urls))  # dedupe, keep order

    signals = scan_signals(ports=ports, urls=url_pool, hosts=hosts)

    by_host: dict[str, list[Signal]] = defaultdict(list)
    for s in signals:
        by_host[s.host].append(s)

    intel_hosts = [HostIntel(host=h, signals=sigs) for h, sigs in by_host.items()]
    intel_hosts.sort(key=lambda h: (-int(h.priority), -h.score, h.host))
    return IntelReport(program=ws.program, hosts=intel_hosts)


def save_report(ws: Workspace, report: IntelReport) -> Path:
    """Persist the report as scans/intel.json for later reporting; record count."""
    path = ws.path("scans", "intel.json")
    fs.write_text(path, json.dumps(report.to_dict(), indent=2))
    ws.state.set_count("intel_signals", len(report.signals))
    return path
