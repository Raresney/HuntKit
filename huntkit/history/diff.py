"""Diff two snapshots — what appeared and what disappeared since last run.

The delta is the whole point of re-running a program: new subdomains to probe,
freshly-live URLs, and above all *new findings*. :func:`diff_snapshots`
compares two :class:`~huntkit.history.store.Snapshot` objects per category;
:func:`current_vs` compares a saved baseline against the workspace as it stands
right now, so ``huntkit diff`` answers "what changed since the baseline?".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.workspace import Workspace
from .store import CATEGORIES, Snapshot, capture


@dataclass
class CategoryDiff:
    name: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


@dataclass
class DiffReport:
    program: str
    base_id: str
    base_time: str
    new_id: str
    new_time: str
    categories: list[CategoryDiff] = field(default_factory=list)

    def by_name(self, name: str) -> CategoryDiff:
        for c in self.categories:
            if c.name == name:
                return c
        return CategoryDiff(name)

    @property
    def changed(self) -> list[CategoryDiff]:
        return [c for c in self.categories if c.changed]

    @property
    def has_changes(self) -> bool:
        return bool(self.changed)

    @property
    def total_added(self) -> int:
        return sum(len(c.added) for c in self.categories)

    @property
    def total_removed(self) -> int:
        return sum(len(c.removed) for c in self.categories)

    @property
    def new_findings(self) -> list[str]:
        return self.by_name("findings").added


def diff_snapshots(old: Snapshot, new: Snapshot, program: str) -> DiffReport:
    """Per-category added/removed between two snapshots (old → new)."""
    cats: list[CategoryDiff] = []
    for name in CATEGORIES:
        old_set = set(old.get(name))
        new_set = set(new.get(name))
        cats.append(
            CategoryDiff(
                name=name,
                added=sorted(new_set - old_set),
                removed=sorted(old_set - new_set),
            )
        )
    return DiffReport(
        program=program,
        base_id=old.id,
        base_time=old.generated,
        new_id=new.id,
        new_time=new.generated,
        categories=cats,
    )


def current_vs(ws: Workspace, baseline: Snapshot) -> tuple[DiffReport, Snapshot]:
    """Diff the workspace as it stands now against ``baseline``.

    Returns the report and the freshly-captured (still unsaved) snapshot, so a
    caller can persist it as the next baseline if asked.
    """
    now = capture(ws)
    return diff_snapshots(baseline, now, ws.program), now
