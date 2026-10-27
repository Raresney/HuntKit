"""Enrichment engine — favicon hashes and ASN origins over the recon surface.

The recon pipeline gathers live URLs and resolved hosts; this layer adds the
two *asset-correlation* signals that turn that surface into leads elsewhere:

  - a **favicon hash** per origin (the Shodan pivot), and
  - the **ASN / BGP prefix** behind each host (the network to sweep next).

It mirrors the scanner's shape — targets are read from the workspace's own,
already scope-filtered result files *and* re-checked against scope here, the
work runs on a thread pool, and results are merged and persisted once on the
main thread. Both the HTTP fetch and the ASN resolve/lookup are injected, so
the engine stays testable without the network.
"""

from __future__ import annotations

import json
import time
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from ..core.workspace import Workspace
from .asn import AsnResult, LookupFn, ResolveFn, asn_for, default_lookup, default_resolve
from .favicon import FaviconResult, FetchFn, hash_favicon

# URL sources (already scope-filtered by recon; re-checked here anyway).
URL_FILES = ["recon/live.txt", "urls/urls.txt"]
HOST_FILES = ["recon/live.txt", "recon/resolved.txt", "urls/urls.txt"]

ENRICH_JSON = "scans/enrich.json"
ENRICH_STATE = "enrich"

_UA = "HuntKit/enrich (+authorised recon)"
_HTTP_TIMEOUT = 10

EventFn = Callable[[dict], None]


@dataclass
class EnrichReport:
    program: str
    favicons: list[FaviconResult] = field(default_factory=list)
    asns: list[AsnResult] = field(default_factory=list)

    @property
    def favicon_hits(self) -> int:
        return sum(1 for f in self.favicons if f.ok)

    @property
    def asn_hits(self) -> int:
        return sum(1 for a in self.asns if a.ok)

    @property
    def unique_asns(self) -> list[str]:
        seen = {a.asn for a in self.asns if a.ok}
        return sorted(seen, key=lambda s: int(s))


def default_fetch(url: str) -> bytes:
    """Fetch a URL's body over HTTP, raising on any non-200 or transport error."""
    # scheme guard first: never let a file:// or other scheme reach urlopen
    if urlparse(url).scheme not in ("http", "https"):
        raise ValueError("only http(s) favicons are fetched")
    req = urllib.request.Request(url, headers={"User-Agent": _UA})  # noqa: S310 — http(s) only
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310
        if resp.status != 200:
            raise OSError(f"HTTP {resp.status}")
        return resp.read()


def _host_of(url: str) -> Optional[str]:
    parsed = urlparse(url if "://" in url else f"//{url}", scheme="http")
    return parsed.hostname


def enrich_origins(ws: Workspace) -> list[str]:
    """One representative URL per in-scope origin (scheme + netloc), deduped."""
    seen: dict[str, str] = {}
    for rel in URL_FILES:
        for url in ws.read_lines(rel):
            parsed = urlparse(url if "://" in url else f"http://{url}")
            host = parsed.hostname
            if not host or not ws.in_scope(host):
                continue
            origin = f"{parsed.scheme}://{parsed.netloc}"
            seen.setdefault(origin, origin)
    return sorted(seen)


def enrich_hosts(ws: Workspace) -> list[str]:
    """Unique in-scope hostnames across the recon result files."""
    seen: dict[str, None] = {}
    for rel in HOST_FILES:
        for line in ws.read_lines(rel):
            host = _host_of(line)
            if host and ws.in_scope(host):
                seen[host] = None
    return sorted(seen)


def run_enrich(
    ws: Workspace,
    *,
    do_favicon: bool = True,
    do_asn: bool = True,
    threads: int = 10,
    fetch: FetchFn = default_fetch,
    resolve: ResolveFn = default_resolve,
    lookup: LookupFn = default_lookup,
    on_event: Optional[EventFn] = None,
) -> EnrichReport:
    """Run the requested enrichers over the workspace and persist the report."""
    emit: EventFn = on_event or (lambda _e: None)
    report = EnrichReport(program=ws.program)
    ws.state.start(ENRICH_STATE)

    if do_favicon:
        origins = enrich_origins(ws)
        emit({"event": "favicon_start", "targets": len(origins)})
        report.favicons = _run_pool(origins, lambda o: hash_favicon(o, fetch), threads)
        emit({"event": "favicon_done", "hits": report.favicon_hits})

    if do_asn:
        hosts = enrich_hosts(ws)
        emit({"event": "asn_start", "targets": len(hosts)})
        report.asns = _run_pool(
            hosts, lambda h: asn_for(h, resolve=resolve, lookup=lookup), threads
        )
        emit({"event": "asn_done", "hits": report.asn_hits})

    _persist(ws, report)
    ws.state.done(ENRICH_STATE, favicons=report.favicon_hits, asns=report.asn_hits)
    return report


def _run_pool(items: list[str], work: Callable[[str], object], threads: int) -> list:
    """Map ``work`` over ``items`` on a thread pool, order-preserving.

    A worker that raises is isolated: the batch keeps its other results.
    """
    if not items:
        return []
    out: dict[int, object] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(items)))) as pool:
        futures = {pool.submit(work, item): i for i, item in enumerate(items)}
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                out[idx] = fut.result()
            except Exception:  # noqa: BLE001 — a crashing worker must not sink the pool
                out[idx] = None
    return [out[i] for i in range(len(items)) if out.get(i) is not None]


def _persist(ws: Workspace, report: EnrichReport) -> None:
    payload = {
        "program": report.program,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "favicons": [f.to_dict() for f in report.favicons],
        "asns": [a.to_dict() for a in report.asns],
    }
    ws.path(ENRICH_JSON).write_text(json.dumps(payload, indent=2), encoding="utf-8")
