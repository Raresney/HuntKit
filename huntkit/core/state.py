"""Scan state, checkpoints, and resume support.

Every pipeline stage records its status so an interrupted run can resume
where it left off and re-run only failed steps. Persisted atomically as JSON
so a crash mid-write can't corrupt it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from ..utils import filesystem as fs


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class StageRecord:
    name: str
    status: StageStatus = StageStatus.PENDING
    started: Optional[float] = None
    finished: Optional[float] = None
    error: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> Optional[float]:
        if self.started and self.finished:
            return self.finished - self.started
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "started": self.started,
            "finished": self.finished,
            "error": self.error,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StageRecord":
        return cls(
            name=data["name"],
            status=StageStatus(data.get("status", "pending")),
            started=data.get("started"),
            finished=data.get("finished"),
            error=data.get("error"),
            meta=data.get("meta", {}),
        )


class StateStore:
    """Persistent stage tracker for one workspace."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.stages: dict[str, StageRecord] = {}
        self.counts: dict[str, int] = {}
        self.created = time.time()
        self.load()

    # ---- persistence -----------------------------------------------------
    def load(self) -> None:
        import json

        if not self.path.exists():
            return
        try:
            data = json.loads(fs.read_text(self.path))
        except (ValueError, OSError):
            return
        self.created = data.get("created", self.created)
        self.counts = data.get("counts", {})
        self.stages = {
            name: StageRecord.from_dict(rec)
            for name, rec in data.get("stages", {}).items()
        }

    def save(self) -> None:
        import json

        payload = {
            "created": self.created,
            "updated": time.time(),
            "counts": self.counts,
            "stages": {name: rec.to_dict() for name, rec in self.stages.items()},
        }
        fs.write_text(self.path, json.dumps(payload, indent=2))

    # ---- stage lifecycle -------------------------------------------------
    def _get(self, stage: str) -> StageRecord:
        if stage not in self.stages:
            self.stages[stage] = StageRecord(name=stage)
        return self.stages[stage]

    def status(self, stage: str) -> StageStatus:
        return self._get(stage).status

    def is_done(self, stage: str) -> bool:
        return self.status(stage) == StageStatus.DONE

    def start(self, stage: str) -> None:
        rec = self._get(stage)
        rec.status = StageStatus.RUNNING
        rec.started = time.time()
        rec.error = None
        self.save()

    def done(self, stage: str, **meta: Any) -> None:
        rec = self._get(stage)
        rec.status = StageStatus.DONE
        rec.finished = time.time()
        rec.meta.update(meta)
        self.save()

    def fail(self, stage: str, error: str) -> None:
        rec = self._get(stage)
        rec.status = StageStatus.FAILED
        rec.finished = time.time()
        rec.error = error
        self.save()

    def skip(self, stage: str) -> None:
        rec = self._get(stage)
        rec.status = StageStatus.SKIPPED
        self.save()

    # ---- resume queries --------------------------------------------------
    def pending(self, all_stages: list[str]) -> list[str]:
        """Stages not yet completed — the resume set."""
        return [s for s in all_stages if not self.is_done(s)]

    def failed(self) -> list[str]:
        return [s for s, r in self.stages.items() if r.status == StageStatus.FAILED]

    def set_count(self, key: str, value: int) -> None:
        self.counts[key] = value
        self.save()

    def reset(self) -> None:
        """Clear all stage state (fresh scan)."""
        self.stages.clear()
        self.save()
