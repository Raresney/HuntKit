"""Persist verification results beside the other scan artifacts.

Results live in scans/verify.json as a flat map of "host|rule_id" to a state
and its evidence. Reading is tolerant: a missing or malformed file yields an
empty map, the same way the intel engine treats scan findings, so a workspace
that was never verified simply stays unverified.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.workspace import Workspace
from ..intel.signals import VerifyState
from ..utils import filesystem as fs
from .engine import VerifyResult

_FILE = ("scans", "verify.json")


def save_results(ws: Workspace, results: dict[tuple[str, str], VerifyResult]) -> Path:
    """Write results to scans/verify.json and return the path."""
    payload = {
        "results": {
            f"{host}|{rule_id}": {"state": result.state.label, "evidence": result.evidence}
            for (host, rule_id), result in results.items()
        }
    }
    path = ws.path(*_FILE)
    fs.write_text(path, json.dumps(payload, indent=2))
    return path


def load_results(ws: Workspace) -> dict[tuple[str, str], VerifyResult]:
    """Read scans/verify.json back, or {} when it is missing or malformed."""
    path = ws.path(*_FILE)
    if not path.exists():
        return {}
    try:
        data = json.loads(fs.read_text(path))
    except (ValueError, OSError):
        return {}
    rows = data.get("results") if isinstance(data, dict) else None
    if not isinstance(rows, dict):
        return {}
    out: dict[tuple[str, str], VerifyResult] = {}
    for key, value in rows.items():
        if not isinstance(value, dict) or "|" not in key:
            continue
        host, _, rule_id = key.partition("|")
        try:
            state = VerifyState[str(value.get("state", "unverified")).upper()]
        except KeyError:
            state = VerifyState.UNVERIFIED
        out[(host, rule_id)] = VerifyResult(state, str(value.get("evidence", "")))
    return out
