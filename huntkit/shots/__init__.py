"""Screenshots layer — a visual of every live URL, for triage and the report.

Drives a headless screenshotter (``gowitness``) over the scope-filtered live
URLs and records a manifest (``scans/screenshots.json``) that the reporting
layer turns into an embedded gallery. Depends only on ``core``; the capture
backend is injectable, so the orchestration is tested without a browser.
"""

from __future__ import annotations

from .runner import (
    SHOTS_DIR,
    SHOTS_JSON,
    Shot,
    ShotSummary,
    gowitness_capture,
    run_shots,
    shot_targets,
)

__all__ = [
    "SHOTS_DIR",
    "SHOTS_JSON",
    "Shot",
    "ShotSummary",
    "gowitness_capture",
    "run_shots",
    "shot_targets",
]
