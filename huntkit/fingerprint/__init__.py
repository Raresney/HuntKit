"""Fingerprint layer — recognise CDN/WAF/cloud/tech from HTTP headers.

A pure feature layer (depends only on ``utils``): it classifies response
headers the operator already captured against a declarative catalog. Offline;
never touches a target.
"""

from __future__ import annotations

from .engine import (
    FingerprintMatch,
    fingerprint_headers,
    has_waf,
    parse_headers,
)
from .rules import FINGERPRINT_RULES, KINDS, FingerprintRule

__all__ = [
    "FINGERPRINT_RULES",
    "FingerprintMatch",
    "FingerprintRule",
    "KINDS",
    "fingerprint_headers",
    "has_waf",
    "parse_headers",
]
