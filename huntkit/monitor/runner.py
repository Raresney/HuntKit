"""Orchestrate one monitor sweep: recon -> snapshot -> diff -> notify."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

from ..core.config import Config
from ..core.workspace import Workspace
from ..history import DiffReport, Snapshot, capture, diff_snapshots, latest, save
from ..notify import PostFn, notify
from ..pipeline import ReconSummary, run_recon

# Injected so a sweep can be driven offline in tests.
ReconFn = Callable[[], ReconSummary]
EventFn = Callable[[dict], None]

# What counts as "worth a ping".
NOTIFY_FINDINGS = "findings"  # only new findings (default — the thing you re-run for)
NOTIFY_CHANGES = "changes"  # any delta at all (new subs/live/urls too)


@dataclass
class MonitorResult:
    program: str
    summary: Optional[ReconSummary]
    report: Optional[DiffReport]  # None on the first run (no baseline yet)
    snapshot: Snapshot
    baseline_id: Optional[str]
    notified: bool
    first_run: bool

    @property
    def has_changes(self) -> bool:
        return bool(self.report and self.report.has_changes)

    @property
    def new_findings(self) -> list[str]:
        return self.report.new_findings if self.report else []


def _should_notify(report: DiffReport, notify_on: str) -> bool:
    if notify_on == NOTIFY_CHANGES:
        return report.has_changes
    return bool(report.new_findings)


def run_monitor(
    ws: Workspace,
    config: Config,
    domain: str,
    *,
    webhook: Optional[str] = None,
    notify_on: str = NOTIFY_FINDINGS,
    recon: Optional[ReconFn] = None,
    post: Optional[PostFn] = None,
    on_event: Optional[EventFn] = None,
) -> MonitorResult:
    """Run one sweep and report what changed since the last saved snapshot.

    The first ever run has no baseline: it just captures a snapshot (the
    baseline for next time) and never notifies. Later runs diff against that
    baseline, save the fresh snapshot, and — if ``webhook`` is set and the
    delta meets ``notify_on`` — push a summary to the webhook.
    """
    emit: EventFn = on_event or (lambda _e: None)

    baseline = latest(ws)
    emit(
        {
            "event": "monitor_start",
            "program": ws.program,
            "baseline": baseline.id if baseline else None,
        }
    )

    do_recon: ReconFn = recon or (lambda: run_recon(ws, config, domain, on_event=on_event))
    emit({"event": "recon_begin"})
    summary = do_recon()

    now = capture(ws)
    save(ws, now)

    report: Optional[DiffReport] = None
    if baseline is not None:
        report = diff_snapshots(baseline, now, ws.program)

    notified = False
    if report is not None and webhook and _should_notify(report, notify_on):
        emit({"event": "notify", "webhook": webhook})
        notified = notify(webhook, report, post=post)

    result = MonitorResult(
        program=ws.program,
        summary=summary,
        report=report,
        snapshot=now,
        baseline_id=baseline.id if baseline else None,
        notified=notified,
        first_run=baseline is None,
    )
    emit(
        {
            "event": "monitor_done",
            "changes": result.has_changes,
            "new_findings": len(result.new_findings),
            "notified": notified,
        }
    )
    return result
