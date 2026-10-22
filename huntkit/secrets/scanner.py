"""Scan gathered text for leaked secrets and JS endpoints.

The scanner matches the pattern catalog against text or files and returns typed
:class:`SecretHit` findings. Every finding's value is **redacted** on the way
out — enough to locate it in the source, never enough to re-leak it — so the
scanner's output (tables, JSON) is safe to store and share.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..utils.severity import Severity
from .patterns import SECRET_PATTERNS, extract_endpoints, shannon_entropy

# Binary / asset extensions never worth scanning as text.
_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg",
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wasm",
    ".exe", ".dll", ".so", ".dylib", ".class", ".pyc",
}
_MAX_BYTES = 8 * 1024 * 1024  # skip files larger than 8 MB


@dataclass(frozen=True)
class SecretHit:
    id: str
    title: str
    severity: Severity
    source: str
    line: int
    match: str          # redacted — safe to print and store

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "source": self.source,
            "line": self.line,
            "match": self.match,
        }


def redact(value: str) -> str:
    """Mask the middle of a secret: keep a few edge chars to locate it."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]}  ({len(value)} chars)"


def scan_text(text: str, *, source: str = "-") -> list[SecretHit]:
    """Find secrets in ``text``, de-duped per (pattern, source, line, value)."""
    hits: list[SecretHit] = []
    seen: set[tuple] = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        for pat in SECRET_PATTERNS:
            for m in pat.regex.finditer(line):
                value = m.group(pat.group)
                if pat.min_entropy and shannon_entropy(value) < pat.min_entropy:
                    continue
                key = (pat.id, source, lineno, value)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(SecretHit(pat.id, pat.title, pat.severity,
                                      source, lineno, redact(value)))
    return hits


def _readable(path: Path) -> str | None:
    if path.suffix.lower() in _SKIP_EXT:
        return None
    try:
        if path.stat().st_size > _MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _walk(paths: list[Path]):
    """Yield (path, text) for every readable file under the given paths."""
    for raw in paths:
        p = Path(raw)
        files = sorted(f for f in p.rglob("*") if f.is_file()) if p.is_dir() else [p]
        for f in files:
            text = _readable(f)
            if text is not None:
                yield f, text


def scan_paths(paths: list[Path]) -> list[SecretHit]:
    """Scan files and directories (recursively) for secrets."""
    hits: list[SecretHit] = []
    for path, text in _walk([Path(p) for p in paths]):
        hits.extend(scan_text(text, source=str(path)))
    return hits


def endpoints_from_paths(paths: list[Path]) -> list[str]:
    """Extract JS endpoints across files and directories, de-duped in order."""
    found: list[str] = []
    for _path, text in _walk([Path(p) for p in paths]):
        found.extend(extract_endpoints(text))
    return list(dict.fromkeys(found))
