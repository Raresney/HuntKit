"""Shared entry point for verification: used by the CLI and by the pipeline.

It rebuilds the candidate signals from the workspace recon files (the same
inputs the intel engine scores), probes the ones that carry a verifier, and
saves the results. Keeping it here means the standalone `verify` command and the
automatic post-recon pass run exactly the same code.
"""

from __future__ import annotations

from ..core.config import Config
from ..core.workspace import Workspace
from ..intel.signals import scan_signals, url_host
from .client import probe
from .engine import ProbeFn, base_for_host, verify_signals
from .store import save_results

# Workspace-relative recon artifacts, mirroring huntkit.intel.engine.
_LIVE = "recon/live.txt"
_URLS = "urls/urls.txt"
_PORTS = "recon/ports.txt"
_SUBS = "recon/subdomains.txt"
_RESOLVED = "recon/resolved.txt"


def _hosts(ws: Workspace, live: list[str]) -> list[str]:
    pool = set(ws.read_lines(_SUBS)) | set(ws.read_lines(_RESOLVED))
    for u in live:
        host = url_host(u)
        if host:
            pool.add(host)
    return sorted(h.lower() for h in pool if h.strip())


def run_verify(ws: Workspace, config: Config, *, probe_fn: ProbeFn = probe) -> int:
    """Probe the workspace's signals and save the results; return the count probed."""
    live = ws.read_lines(_LIVE)
    urls = ws.read_lines(_URLS)
    ports = ws.read_lines(_PORTS)
    hosts = _hosts(ws, live)
    url_pool = list(dict.fromkeys(live + urls))

    signals = scan_signals(ports=ports, urls=url_pool, hosts=hosts)
    results = verify_signals(
        signals,
        bases=base_for_host(live),
        in_scope=ws.in_scope,
        probe_fn=probe_fn,
        delay=config.http.delay,
        timeout=10.0,
        user_agent=config.http.user_agent,
        headers=config.http.headers,
        proxy=config.http.proxy,
    )
    save_results(ws, results)
    return len(results)
