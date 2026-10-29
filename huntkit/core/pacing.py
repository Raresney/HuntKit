"""Politeness — one policy that paces every rate-aware tool.

Real bug-bounty programs ban noisy scanners, and "authorised" does not mean
"hammer the target". HuntKit keeps a single rate / delay / concurrency policy
(from config) and maps it onto each tool's native flags, so dialing a program
down to a gentle crawl is one edit, not twelve scattered ones.

Pure and offline: it only turns the policy into argv fragments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Config


@dataclass(frozen=True)
class Pace:
    """The politeness policy, normalised from config.

    ``rate`` is HTTP requests/sec; ``port_rate`` is packets/sec for the port
    scanner (a different budget); ``delay`` is seconds between requests for the
    tools that support it; ``concurrency`` caps workers. A zero rate/delay
    means "no limit" / "no wait".
    """

    rate: int
    port_rate: int
    delay: float
    concurrency: int

    @classmethod
    def from_config(cls, config: Config) -> Pace:
        return cls(
            rate=max(0, config.http.rate_limit),
            port_rate=max(0, config.general.rate),
            delay=max(0.0, config.http.delay),
            concurrency=max(1, config.general.threads),
        )


def duration(seconds: float) -> str:
    """Render seconds as a ProjectDiscovery duration string: '500ms', '2s'."""
    if seconds < 1:
        return f"{int(round(seconds * 1000))}ms"
    whole = int(seconds)
    return f"{whole}s" if seconds == whole else f"{seconds}s"


def rate_arg(flag: str, rate: int) -> list[str]:
    """``[flag, rate]`` when a positive limit is set, else nothing."""
    return [flag, str(rate)] if rate > 0 else []


def delay_arg(flag: str, seconds: float, *, unit: str = "pd") -> list[str]:
    """``[flag, value]`` for an inter-request delay, in the tool's own unit.

    ``unit`` picks the rendering: ``pd`` → a ProjectDiscovery duration string
    ('500ms'), ``sec`` → plain fractional seconds (ffuf ``-p``), ``ms`` → whole
    milliseconds (dalfox ``--delay``). A non-positive delay emits nothing.
    """
    if seconds <= 0:
        return []
    if unit == "sec":
        return [flag, str(seconds)]
    if unit == "ms":
        return [flag, str(int(round(seconds * 1000)))]
    return [flag, duration(seconds)]
