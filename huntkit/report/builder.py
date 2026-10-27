"""Assemble an engagement report from everything a workspace holds.

A :class:`Report` is the composition layer: it runs the intelligence engine
over the recon surface, pulls the referenced playbooks out of the knowledge
base, and pairs them with scope and recon counts. The renderers
(:mod:`huntkit.report.render`) turn this one model into Markdown, HTML, or
JSON, so every format shows exactly the same facts.

Pure and offline — it only reads artifacts already on disk.
"""

from __future__ import annotations

import base64
import json
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

_SHOTS_MANIFEST = "scans/screenshots.json"
_MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}


@dataclass
class Screenshot:
    """One captured URL and, for the HTML renderer, its inlined image.

    ``data_uri`` is populated by the builder (which can read the file) so the
    HTML report stays a single self-contained page; it is deliberately left
    out of :meth:`to_dict` so JSON/Markdown reference the file by path.
    """

    url: str
    file: str  # relative to the workspace root
    data_uri: str = ""

    def to_dict(self) -> dict:
        return {"url": self.url, "file": self.file}


@dataclass
class Report:
    program: str
    scope_in: list[str]
    scope_out: list[str]
    recon: dict[str, int]  # stage -> asset count
    intel: IntelReport
    playbooks: list[Playbook]  # referenced by attack paths, severity order
    screenshots: list[Screenshot] = field(default_factory=list)
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
            "screenshots": [s.to_dict() for s in self.screenshots],
        }


def _referenced_playbooks(intel: IntelReport) -> list[Playbook]:
    """The playbooks the attack paths point at, most-severe first, de-duped."""
    out: list[Playbook] = []
    seen: set[str] = set()
    for path in intel.attack_paths():  # already severity-ranked
        if path.playbook in seen:
            continue
        pb = get_playbook(path.playbook)
        if pb is not None:
            out.append(pb)
            seen.add(path.playbook)
    return out


def _load_screenshots(ws: Workspace) -> list[Screenshot]:
    """Read the screenshot manifest and inline each image for the HTML report.

    Missing or malformed manifests yield no screenshots; an image file that
    has gone missing is dropped rather than erroring the whole report.
    """
    manifest = ws.path(_SHOTS_MANIFEST)
    if not manifest.exists():
        return []
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        entries = data.get("shots", [])
    except (ValueError, OSError):
        return []

    out: list[Screenshot] = []
    for entry in entries:
        rel = entry.get("file", "")
        url = entry.get("url", "")
        if not rel or not url:
            continue
        shot = Screenshot(url=url, file=rel)
        img = ws.path(rel)
        mime = _MIME.get(img.suffix.lower())
        if mime and img.exists():
            try:
                raw = base64.b64encode(img.read_bytes()).decode("ascii")
                shot.data_uri = f"data:{mime};base64,{raw}"
            except OSError:
                pass
        out.append(shot)
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
        screenshots=_load_screenshots(ws),
    )
