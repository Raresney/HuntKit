"""History layer — snapshot a program's results and diff across runs.

Bug bounty is the same scope re-swept over time; this layer freezes the
workspace's result sets into timestamped snapshots (``history/``) and reports
the delta between two points — new subdomains, freshly-live URLs, and above
all new findings. Depends only on ``core``; pure and offline.
"""

from __future__ import annotations

from .diff import CategoryDiff, DiffReport, current_vs, diff_snapshots
from .store import (
    CATEGORIES,
    HISTORY_DIR,
    Snapshot,
    capture,
    find,
    latest,
    list_snapshots,
    load,
    save,
)

__all__ = [
    "CATEGORIES",
    "HISTORY_DIR",
    "CategoryDiff",
    "DiffReport",
    "Snapshot",
    "capture",
    "current_vs",
    "diff_snapshots",
    "find",
    "latest",
    "list_snapshots",
    "load",
    "save",
]
