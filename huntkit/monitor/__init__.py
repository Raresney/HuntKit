"""Monitor layer — continuous re-sweep with delta notification.

Bug bounty is the same scope re-run over time; the signal is the delta. This
layer runs one sweep (recon), snapshots the result set, diffs it against the
saved baseline, persists the new snapshot as the next baseline, and fires a
webhook when something new turns up. Recon and the webhook POST are injected,
so the orchestration is exercised offline.
"""

from __future__ import annotations

from .runner import (
    NOTIFY_CHANGES,
    NOTIFY_FINDINGS,
    MonitorResult,
    run_monitor,
)

__all__ = [
    "NOTIFY_CHANGES",
    "NOTIFY_FINDINGS",
    "MonitorResult",
    "run_monitor",
]
