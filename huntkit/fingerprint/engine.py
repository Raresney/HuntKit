"""Fingerprint engine — classify HTTP response headers against the catalog.

Accepts either a parsed header mapping or a raw header block (as printed by
``curl -sI`` or saved from a response), and returns the vendors it recognises,
WAF first. Pure: it only reads headers the operator already captured.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..utils.severity import Severity
from .rules import FINGERPRINT_RULES, KINDS

_KIND_ORDER = {k: i for i, k in enumerate(KINDS)}


@dataclass(frozen=True)
class FingerprintMatch:
    id: str
    name: str
    kind: str
    severity: Severity
    evidence: str          # the header that matched, e.g. "cf-ray: 7a1b…"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "severity": self.severity.label,
            "evidence": self.evidence,
        }


def parse_headers(text: str) -> dict[str, str]:
    """Parse a raw header block into a lowercased name->value map.

    The HTTP status line is skipped and repeated headers (notably Set-Cookie)
    are joined with '; ' so a single substring check still sees them all.
    """
    headers: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if not name or name.startswith("http/"):
            continue
        headers[name] = f"{headers[name]}; {value}" if name in headers else value
    return headers


def _evidence(rule, headers: dict[str, str]) -> str:
    for hname, vsub in rule.headers:
        val = headers.get(hname)
        if val is None:
            continue
        if vsub == "" or vsub in val.lower():
            shown = val if len(val) <= 60 else val[:57] + "…"
            return f"{hname}: {shown}"
    return ""


def fingerprint_headers(headers: str | dict) -> list[FingerprintMatch]:
    """Return matched vendors for the given headers, WAF first then by kind."""
    hmap = (
        parse_headers(headers) if isinstance(headers, str)
        else {str(k).lower(): str(v) for k, v in headers.items()}
    )
    out: list[FingerprintMatch] = []
    for rule in FINGERPRINT_RULES:
        ev = _evidence(rule, hmap)
        if ev:
            out.append(FingerprintMatch(rule.id, rule.name, rule.kind, rule.severity, ev))
    out.sort(key=lambda m: (-int(m.severity), _KIND_ORDER.get(m.kind, 9), m.name))
    return out


def has_waf(matches: list[FingerprintMatch]) -> bool:
    return any(m.kind == "waf" for m in matches)
