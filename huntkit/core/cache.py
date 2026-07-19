"""Content-addressed result cache.

Skips re-running an expensive tool when the same command + input has already
produced output within a TTL. Keys are hashes so the same passive enumeration
isn't repeated across runs of a workspace. Entirely local; lives in the
workspace `cache/` directory.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

from ..utils import filesystem as fs


def make_key(*parts: str) -> str:
    """Stable cache key from arbitrary string parts (tool, args, stdin)."""
    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
    return digest[:32]


class Cache:
    def __init__(self, root: Path, ttl_seconds: int = 86_400, enabled: bool = True) -> None:
        self.root = root
        self.ttl = ttl_seconds
        self.enabled = enabled

    def _path(self, key: str) -> Path:
        return self.root / f"{key}.json"

    def get(self, key: str) -> Optional[str]:
        if not self.enabled:
            return None
        path = self._path(key)
        if not path.exists():
            return None
        try:
            record = json.loads(fs.read_text(path))
        except (json.JSONDecodeError, OSError):
            return None
        if self.ttl and time.time() - record.get("ts", 0) > self.ttl:
            return None
        return record.get("value")

    def set(self, key: str, value: str) -> None:
        if not self.enabled:
            return
        fs.ensure_dir(self.root)
        fs.write_text(self._path(key), json.dumps({"ts": time.time(), "value": value}))

    def invalidate(self, key: str) -> None:
        path = self._path(key)
        if path.exists():
            path.unlink()

    def clear(self) -> int:
        if not self.root.exists():
            return 0
        removed = 0
        for f in self.root.glob("*.json"):
            f.unlink()
            removed += 1
        return removed
