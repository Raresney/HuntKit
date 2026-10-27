"""Favicon hashing — the Shodan pivot from one icon to every host serving it.

A favicon is a strong asset-correlation signal: load balancers, dev/staging
mirrors, and forgotten origins behind a CDN very often ship the *same* icon as
the flagship site. Hashing it (``mmh3`` over the base64 of the raw bytes, the
Shodan convention) gives a single integer you can paste into
``http.favicon.hash:<h>`` on Shodan/Censys to surface the rest of the estate.

The fetch is a plain HTTP GET to an in-scope target — the same kind of request
recon already makes — and is injectable so the engine (and the tests) can swap
in a stubbed fetcher instead of hitting the network.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

from . import mmh3

# Fetcher contract: given an absolute URL, return the response body bytes, or
# raise on any failure (timeout, non-200, connection error). The engine wraps
# the default urllib fetcher so callers can inject a stub in tests.
FetchFn = Callable[[str], bytes]

_MAX_BYTES = 1024 * 1024  # a favicon over 1 MiB is not a favicon


@dataclass
class FaviconResult:
    """One host's favicon hash and the search pivot it unlocks."""

    url: str
    hash: Optional[int] = None
    size: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.hash is not None

    @property
    def shodan(self) -> str:
        return f"http.favicon.hash:{self.hash}" if self.ok else ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "hash": self.hash,
            "size": self.size,
            "shodan": self.shodan,
            "error": self.error,
        }


def favicon_url(base: str) -> str:
    """The ``/favicon.ico`` URL for a site, given any URL on that origin."""
    parsed = urlparse(base if "://" in base else f"http://{base}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return urljoin(origin + "/", "favicon.ico")


def favicon_hash(data: bytes) -> int:
    """The Shodan-convention favicon hash: mmh3 over the base64 of the bytes.

    ``base64.encodebytes`` is used (not ``b64encode``) because it inserts a
    newline every 76 chars and a trailing newline — the exact byte stream
    Shodan hashes, so the result matches ``http.favicon.hash:`` queries.
    """
    return mmh3.hash_bytes(base64.encodebytes(data))


def hash_favicon(base_url: str, fetch: FetchFn) -> FaviconResult:
    """Fetch the favicon for ``base_url`` and hash it, never raising.

    A fetch failure (missing icon, timeout, oversize) is recorded on the
    result rather than propagated, so one dead host cannot sink a batch.
    """
    url = favicon_url(base_url)
    try:
        data = fetch(url)
    except Exception as exc:  # noqa: BLE001 — a bad fetch is data, not a crash
        return FaviconResult(url=url, error=str(exc) or type(exc).__name__)
    if not data:
        return FaviconResult(url=url, error="empty response")
    if len(data) > _MAX_BYTES:
        return FaviconResult(url=url, size=len(data), error="too large")
    return FaviconResult(url=url, hash=favicon_hash(data), size=len(data))
