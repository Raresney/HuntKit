"""Snapshots — freeze a program's result set so later runs can be diffed.

Bug bounty is not one pass; it is the same scope re-run over weeks. The signal
that matters is the *delta*: a subdomain that appeared yesterday, a URL that
went live, a finding that is new since the last sweep. This layer captures the
current state of a workspace's result files into a timestamped snapshot under
``history/`` so :mod:`huntkit.history.diff` can compare two points in time.

Pure and offline — it only reads artifacts already on disk.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..core.workspace import Workspace

HISTORY_DIR = "history"
_FINDINGS_JSON = "scans/findings.json"

# The result sets a snapshot freezes, in pipeline order. Each text category
# maps to a deduped result file; ``findings`` is flattened from the scan JSON.
CATEGORIES: tuple[str, ...] = ("subdomains", "resolved", "live", "ports", "urls", "findings")
_FILE_SOURCES: dict[str, str] = {
    "subdomains": "recon/subdomains.txt",
    "resolved": "recon/resolved.txt",
    "live": "recon/live.txt",
    "ports": "recon/ports.txt",
    "urls": "urls/urls.txt",
}


@dataclass
class Snapshot:
    """One frozen point in time: the sorted, deduped items per category."""

    id: str  # sortable stamp, e.g. 20261027-163000
    generated: str  # ISO-8601 UTC
    items: dict[str, list[str]] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        return {cat: len(self.items.get(cat, [])) for cat in CATEGORIES}

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.items.values())

    def get(self, category: str) -> list[str]:
        return self.items.get(category, [])

    def to_dict(self) -> dict:
        return {"id": self.id, "generated": self.generated, "items": self.items}

    @classmethod
    def from_dict(cls, data: dict) -> Snapshot:
        raw = data.get("items", {})
        items = {cat: list(raw.get(cat, [])) for cat in CATEGORIES}
        return cls(id=data.get("id", ""), generated=data.get("generated", ""), items=items)


def _findings(ws: Workspace) -> list[str]:
    """Flatten the combined scan findings into a sorted, deduped list."""
    path = ws.path(_FINDINGS_JSON)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return []
    seen: set[str] = set()
    for lines in data.get("tools", {}).values():
        seen.update(ln for ln in lines if ln.strip())
    return sorted(seen)


def capture(ws: Workspace) -> Snapshot:
    """Freeze the workspace's current result sets into an unsaved snapshot."""
    items: dict[str, list[str]] = {}
    for cat, rel in _FILE_SOURCES.items():
        items[cat] = sorted(dict.fromkeys(ws.read_lines(rel)))
    items["findings"] = _findings(ws)
    return Snapshot(
        id=time.strftime("%Y%m%d-%H%M%S", time.gmtime()),
        generated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        items=items,
    )


def save(ws: Workspace, snap: Snapshot) -> Path:
    """Persist a snapshot under ``history/<id>.json`` and return its path."""
    outdir = Path(ws.path(HISTORY_DIR))
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / f"{snap.id}.json"
    path.write_text(json.dumps(snap.to_dict(), indent=2), encoding="utf-8")
    return path


def load(path: Path) -> Snapshot:
    return Snapshot.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def list_snapshots(ws: Workspace) -> list[Snapshot]:
    """All saved snapshots, oldest first (sorted by id)."""
    outdir = Path(ws.path(HISTORY_DIR))
    if not outdir.exists():
        return []
    snaps = []
    for p in outdir.glob("*.json"):
        try:
            snaps.append(load(p))
        except (ValueError, OSError):
            continue
    return sorted(snaps, key=lambda s: s.id)


def latest(ws: Workspace) -> Snapshot | None:
    snaps = list_snapshots(ws)
    return snaps[-1] if snaps else None


def find(ws: Workspace, snapshot_id: str) -> Snapshot | None:
    """Look up a snapshot by exact id, or None."""
    path = Path(ws.path(HISTORY_DIR)) / f"{snapshot_id}.json"
    if not path.exists():
        return None
    try:
        return load(path)
    except (ValueError, OSError):
        return None
