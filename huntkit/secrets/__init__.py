"""Secret & JS-endpoint scanner — mine gathered content for leaks.

A pure feature layer (depends only on ``utils``): it matches a declarative
pattern catalog against text the operator already collected and returns
redacted findings. Offline; never touches a target.
"""

from __future__ import annotations

from .patterns import (
    SECRET_PATTERNS,
    SecretPattern,
    extract_endpoints,
    shannon_entropy,
)
from .scanner import (
    SecretHit,
    endpoints_from_paths,
    redact,
    scan_paths,
    scan_text,
)

__all__ = [
    "SECRET_PATTERNS",
    "SecretHit",
    "SecretPattern",
    "endpoints_from_paths",
    "extract_endpoints",
    "redact",
    "scan_paths",
    "scan_text",
    "shannon_entropy",
]
