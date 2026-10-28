"""Chat-webhook delivery for monitor deltas (Slack / Discord incoming hooks)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..history import DiffReport

# POST a JSON payload to a URL; return True iff delivered. Injected in tests so
# nothing leaves the box.
PostFn = Callable[[str, dict], bool]

_TIMEOUT = 10
_ALLOWED_SCHEMES = ("http", "https")
_MAX_LISTED = 10  # cap how many new items we spell out before summarising


def _is_discord(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname or ""
    return host.endswith("discord.com") or host.endswith("discordapp.com")


def summarise(report: DiffReport) -> str:
    """One compact, human-readable block describing the delta."""
    lines = [f"HuntKit · {report.program} — changes since {report.base_id}"]
    for cat in report.changed:
        parts = []
        if cat.added:
            parts.append(f"+{len(cat.added)}")
        if cat.removed:
            parts.append(f"-{len(cat.removed)}")
        lines.append(f"  {cat.name}: {' '.join(parts)}")

    new = report.new_findings
    if new:
        lines.append(f"NEW FINDINGS ({len(new)}):")
        lines.extend(f"  • {item}" for item in new[:_MAX_LISTED])
        if len(new) > _MAX_LISTED:
            lines.append(f"  … and {len(new) - _MAX_LISTED} more")
    return "\n".join(lines)


def _payload(url: str, text: str) -> dict:
    # Slack expects {"text": …}; Discord expects {"content": …}. Send the key
    # the target renders, keyed off the host.
    return {"content": text} if _is_discord(url) else {"text": text}


def default_post(url: str, payload: dict) -> bool:
    """POST ``payload`` as JSON. Scheme-guarded to http(s); never raises on a
    network error — a down webhook shouldn't crash a sweep."""
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"refusing non-http(s) webhook URL (scheme: {scheme or 'none'})")
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def notify(url: str, report: DiffReport, *, post: Optional[PostFn] = None) -> bool:
    """Send the diff summary to the webhook. Returns True if delivered."""
    sender = post or default_post
    return sender(url, _payload(url, summarise(report)))
