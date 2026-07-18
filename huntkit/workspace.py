"""Per-program workspace: folder layout, state, and deduped result files.

A workspace lives under ~/.huntkit/<program> by default (override with
--workspace or the HUNTKIT_HOME env var). It keeps recon output on disk so
scans and reports can be re-run without repeating enumeration.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


def home() -> Path:
    env = os.environ.get("HUNTKIT_HOME")
    base = Path(env).expanduser() if env else Path.home() / ".huntkit"
    return base


# Subdirectories created inside every workspace.
LAYOUT = ["scope", "recon", "urls", "scans", "notes", "loot", "reports"]


@dataclass
class Workspace:
    program: str
    root: Path
    state: dict = field(default_factory=dict)

    @classmethod
    def open(cls, program: str, base: Path | None = None) -> "Workspace":
        base = base or home()
        root = base / _safe(program)
        ws = cls(program=program, root=root)
        ws._ensure_layout()
        ws._load_state()
        return ws

    # ---- filesystem ------------------------------------------------------
    def _ensure_layout(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for sub in LAYOUT:
            (self.root / sub).mkdir(exist_ok=True)

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    # ---- state (audit log of what has run) -------------------------------
    @property
    def _state_file(self) -> Path:
        return self.root / "state.json"

    def _load_state(self) -> None:
        if self._state_file.exists():
            try:
                self.state = json.loads(self._state_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self.state = {}
        self.state.setdefault("program", self.program)
        self.state.setdefault("created", _now())
        self.state.setdefault("runs", [])
        self.state.setdefault("counts", {})
        self.state.setdefault("scope", {"in": [], "out": []})

    def save(self) -> None:
        self.state["updated"] = _now()
        self._state_file.write_text(json.dumps(self.state, indent=2), encoding="utf-8")

    def record_run(self, action: str, detail: str = "", **meta) -> None:
        self.state["runs"].append({
            "action": action, "detail": detail, "when": _now(), **meta
        })
        self.save()

    def set_count(self, key: str, value: int) -> None:
        self.state["counts"][key] = value
        self.save()

    # ---- scope -----------------------------------------------------------
    def set_scope(self, in_scope: list[str], out_scope: list[str]) -> None:
        self.state["scope"] = {"in": in_scope, "out": out_scope}
        (self.root / "scope" / "in_scope.txt").write_text(
            "\n".join(in_scope) + "\n", encoding="utf-8")
        (self.root / "scope" / "out_scope.txt").write_text(
            "\n".join(out_scope) + "\n", encoding="utf-8")
        self.save()

    def in_scope(self, host: str) -> bool:
        """True if host matches an in-scope pattern and no out-of-scope one.

        Patterns support a leading '*.' wildcard (e.g. *.example.com).
        With no scope defined, everything is considered in scope.
        """
        scope = self.state.get("scope", {})
        outs = scope.get("out", [])
        ins = scope.get("in", [])
        if any(_match(host, p) for p in outs):
            return False
        if not ins:
            return True
        return any(_match(host, p) for p in ins)

    # ---- deduped result sets --------------------------------------------
    def append_unique(self, relpath: str, items: Iterable[str]) -> int:
        """Merge `items` into a file, keeping it sorted & unique.

        Returns the count of newly added lines.
        """
        target = self.root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        existing = set()
        if target.exists():
            existing = {ln.strip() for ln in target.read_text(encoding="utf-8").splitlines() if ln.strip()}
        incoming = {i.strip() for i in items if i and i.strip()}
        new = incoming - existing
        merged = sorted(existing | incoming)
        target.write_text("\n".join(merged) + ("\n" if merged else ""), encoding="utf-8")
        return len(new)

    def read_lines(self, relpath: str) -> list[str]:
        target = self.root / relpath
        if not target.exists():
            return []
        return [ln.strip() for ln in target.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def exists(self, relpath: str) -> bool:
        return (self.root / relpath).exists()


# ---- helpers -------------------------------------------------------------
def _safe(name: str) -> str:
    keep = "-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    cleaned = "".join(c if c in keep else "_" for c in name).strip("_")
    return cleaned or "default"


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _match(host: str, pattern: str) -> bool:
    host = host.lower().strip()
    pattern = pattern.lower().strip()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host == pattern[2:] or host.endswith(suffix)
    return host == pattern


def list_workspaces(base: Path | None = None) -> list[str]:
    base = base or home()
    if not base.exists():
        return []
    return sorted(p.name for p in base.iterdir() if p.is_dir() and (p / "state.json").exists())
