"""Assemble an engagement report from everything a workspace holds.

A :class:`Report` is the composition layer: it runs the intelligence engine
over the recon surface, pulls the referenced playbooks out of the knowledge
base, and pairs them with scope and recon counts. The renderers
(:mod:`huntkit.report.render`) turn this one model into Markdown, HTML, or
JSON, so every format shows exactly the same facts.

Pure and offline — it only reads artifacts already on disk.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..core.workspace import Workspace
from ..intel import IntelReport, analyze
from ..knowledge import Playbook, get_playbook

# Recon artifacts summarised in the report, in pipeline order.
_RECON_FILES: tuple[tuple[str, str], ...] = (
    ("subdomains", "recon/subdomains.txt"),
    ("resolved", "recon/resolved.txt"),
    ("live", "recon/live.txt"),
    ("ports", "recon/ports.txt"),
    ("urls", "urls/urls.txt"),
)


@dataclass
class Report:
    program: str
    scope_in: list[str]
    scope_out: list[str]
    recon: dict[str, int]          # stage -> asset count
    intel: IntelReport
    playbooks: list[Playbook]      # referenced by attack paths, severity order
    generated: float = field(default_factory=time.time)

    @property
    def has_findings(self) -> bool:
        return bool(self.intel.signals)

    @property
    def has_data(self) -> bool:
        """True if there is anything worth writing — findings or recon assets."""
        return self.has_findings or any(self.recon.values())

    def to_dict(self) -> dict:
        return {
            "program": self.program,
            "generated": self.generated,
            "scope": {"in": self.scope_in, "out": self.scope_out},
            "recon": self.recon,
            "intel": self.intel.to_dict(),
            "playbooks": [p.to_dict() for p in self.playbooks],
        }


def _referenced_playbooks(intel: IntelReport) -> list[Playbook]:
    """The playbooks the attack paths point at, most-severe first, de-duped."""
    out: list[Playbook] = []
    seen: set[str] = set()
    for path in intel.attack_paths():          # already severity-ranked
        if path.playbook in seen:
            continue
        pb = get_playbook(path.playbook)
        if pb is not None:
            out.append(pb)
            seen.add(path.playbook)
    return out


def build(ws: Workspace) -> Report:
    """Score the workspace and gather everything a report needs."""
    intel = analyze(ws)
    recon = {label: ws.count(rel) for label, rel in _RECON_FILES}
    return Report(
        program=ws.program,
        scope_in=ws.scope_in,
        scope_out=ws.scope_out,
        recon=recon,
        intel=intel,
        playbooks=_referenced_playbooks(intel),
    )
