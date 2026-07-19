"""Filesystem helpers: atomic writes, deduped line sets, safe joins.

All text I/O is UTF-8 with newline normalisation so results are identical on
Windows and Linux (the original tool produced cp1252 mojibake on Windows).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Iterable

ENCODING = "utf-8"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_text(path: Path, default: str = "") -> str:
    if not path.exists():
        return default
    return path.read_text(encoding=ENCODING)


def write_text(path: Path, data: str) -> None:
    """Atomically write text: write to a temp file, then replace.

    Prevents half-written files if the process is interrupted mid-write —
    important for state.json and long result sets.
    """
    ensure_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=ENCODING, newline="\n") as fh:
            fh.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [ln.strip() for ln in read_text(path).splitlines() if ln.strip()]


def append_unique(path: Path, items: Iterable[str]) -> int:
    """Merge items into a sorted, unique line file. Returns count of new lines.

    This is the `anew`-style primitive the whole recon pipeline relies on to
    never store the same asset twice.
    """
    incoming = {i.strip() for i in items if i and i.strip()}
    if not incoming and not path.exists():
        return 0
    existing = set(read_lines(path))
    new = incoming - existing
    if not new and path.exists():
        return 0
    merged = sorted(existing | incoming)
    write_text(path, "\n".join(merged) + ("\n" if merged else ""))
    return len(new)


def count_lines(path: Path) -> int:
    return len(read_lines(path))


def safe_join(base: Path, *parts: str) -> Path:
    """Join under `base`, refusing any result that escapes it (traversal guard)."""
    base = base.resolve()
    target = base.joinpath(*parts).resolve()
    if base != target and base not in target.parents:
        raise ValueError(f"path escapes workspace: {target}")
    return target


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"
