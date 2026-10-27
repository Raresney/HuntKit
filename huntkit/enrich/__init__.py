"""Enrichment layer — asset-correlation signals over the recon surface.

Two enrichers that turn a gathered surface into leads *elsewhere*:

  - **favicon** — the Shodan-convention favicon hash (``http.favicon.hash:``),
    the pivot from one icon to every host serving it;
  - **asn** — the ASN / BGP prefix a host is announced from, the network block
    to sweep for sibling assets.

Depends only on ``core`` (workspace/scope) and ``utils``; both the HTTP fetch
and the ASN resolve/lookup are injectable, so the layer is offline in tests.
"""

from __future__ import annotations

from .asn import AsnResult, asn_for, parse_cymru
from .engine import (
    ENRICH_JSON,
    EnrichReport,
    enrich_hosts,
    enrich_origins,
    run_enrich,
)
from .favicon import FaviconResult, favicon_hash, favicon_url, hash_favicon

__all__ = [
    "ENRICH_JSON",
    "AsnResult",
    "EnrichReport",
    "FaviconResult",
    "asn_for",
    "enrich_hosts",
    "enrich_origins",
    "favicon_hash",
    "favicon_url",
    "hash_favicon",
    "parse_cymru",
    "run_enrich",
]
