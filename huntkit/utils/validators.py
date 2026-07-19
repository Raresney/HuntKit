"""Input validation and sanitisation.

Security-critical: HuntKit hands user-supplied domains straight to external
tools and uses program/target names to build filesystem paths. Everything
that crosses those boundaries is validated here.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# RFC-1123-ish hostname: labels of [a-z0-9-], 1-63 chars, no leading/trailing
# hyphen, at least one dot. Wildcards handled separately.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")
_WILDCARD_RE = re.compile(rf"^\*\.{_LABEL}(?:\.{_LABEL})+$")


class ValidationError(ValueError):
    """Raised when user input fails validation."""


def is_domain(value: str) -> bool:
    """True for a bare hostname like ``api.example.com`` (no scheme/port)."""
    value = value.strip().lower()
    return bool(_DOMAIN_RE.match(value)) and len(value) <= 253


def is_wildcard(value: str) -> bool:
    """True for a wildcard scope entry like ``*.example.com``."""
    return bool(_WILDCARD_RE.match(value.strip().lower()))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_scope_entry(value: str) -> bool:
    """Accept a bare domain, a wildcard domain, or an IP/CIDR."""
    value = value.strip().lower()
    if is_domain(value) or is_wildcard(value) or is_ip(value):
        return True
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_url(value: str) -> bool:
    try:
        parsed = urlparse(value.strip())
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except ValueError:
        return False


def normalise_domain(value: str) -> str:
    """Strip scheme, path, port, and lowercase — yield a bare hostname.

    Raises ValidationError if the result is not a valid domain, so callers
    never pass junk to a subprocess.
    """
    raw = value.strip().lower()
    if "://" in raw:
        raw = urlparse(raw).netloc or raw
    raw = raw.split("/")[0].split(":")[0].strip(".")
    if not is_domain(raw):
        raise ValidationError(f"not a valid domain: {value!r}")
    return raw


# Characters allowed in a filesystem-safe slug.
_SAFE_CHARS = frozenset(
    "-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)


def sanitize_filename(name: str, *, fallback: str = "default", max_len: int = 120) -> str:
    """Turn arbitrary text into a safe single-path-segment filename.

    Prevents path traversal (no ``/``, ``\\``, ``..``) and control chars.
    """
    cleaned = "".join(c if c in _SAFE_CHARS else "_" for c in name).strip("._")
    cleaned = cleaned[:max_len]
    # collapse runs of underscores for readability
    cleaned = re.sub(r"_{2,}", "_", cleaned)
    if not cleaned or cleaned in {".", ".."}:
        return fallback
    return cleaned


def is_wildcard_scope_risky(entries: list[str]) -> bool:
    """True if scope contains a broad wildcard worth warning the user about."""
    return any(is_wildcard(e) for e in entries)
