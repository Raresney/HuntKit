r"""Active scanning — drive the vuln/fuzz toolchain over gathered URLs.

The recon pipeline *discovers* assets; :func:`run_scan` is the active phase
that runs the ``SCAN``-category plugins (nuclei, dalfox, …) over the live URLs
recon found and records their findings.

It deliberately reuses the recon pipeline's machinery rather than inventing a
second one:

  - **same plugin contract** — a scanner is just a ``ToolPlugin`` whose
    category is :data:`Category.SCAN`; a new one is one file, picked up with
    no change here;
  - **same concurrency model** — every available scanner runs on a thread
    pool, results merged once on the main thread;
  - **same safety model** — targets are read from the workspace's already
    scope-filtered result files *and* re-checked against the program scope
    here, so the active phase can never reach a host recon would have refused.

Only STDIN scanners (those that take the whole URL list at once, e.g. nuclei,
dalfox) run in this batch. Per-URL fuzzers (ffuf, arjun) have a different
shape and are driven separately; they are reported as such, not silently
dropped.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from ..core.config import Config
from ..core.runner import CommandRunner
from ..core.workspace import Workspace
from ..plugins import (
    Capability,
    Category,
    InputMode,
    PluginContext,
    PluginResult,
    ToolPlugin,
    get_registry,
)
from ..plugins.registry import PluginRegistry

# Files the scanner reads its candidate URLs from, in order. Both are written
# by recon and are already scope-filtered at discovery; we re-filter anyway.
TARGET_FILES = ["recon/live.txt", "urls/urls.txt"]

# Where a scan writes. Per-tool raw output plus one combined JSON.
FINDINGS_JSON = "scans/findings.json"
SCAN_STATE = "scan"

EventFn = Callable[[dict], None]


@dataclass
class ScanOutcome:
    tool: str
    findings: list[str] = field(default_factory=list)
    ran: bool = False
    skipped: bool = False
    reason: str = ""

    @property
    def count(self) -> int:
        return len(self.findings)


@dataclass
class ScanSummary:
    program: str
    targets: int = 0
    outcomes: list[ScanOutcome] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(o.count for o in self.outcomes if o.ran)

    @property
    def ran(self) -> list[str]:
        return [o.tool for o in self.outcomes if o.ran]


def scan_plugins(registry: PluginRegistry) -> list[ToolPlugin]:
    """The batch scanners: SCAN-category plugins that consume a URL list via stdin."""
    return [p for p in registry.by_category(Category.SCAN) if p.input_mode is InputMode.STDIN]


def scan_targets(ws: Workspace) -> list[str]:
    """Collect candidate URLs from the workspace, deduped and scope-checked.

    A URL survives only if its host is in scope for the program. With no scope
    set the workspace treats everything as in scope, but recon always sets at
    least ``*.<seed>`` — so the active phase stays bounded either way.
    """
    seen: dict[str, None] = {}
    for rel in TARGET_FILES:
        for url in ws.read_lines(rel):
            host = _host_of(url)
            if host and ws.in_scope(host):
                seen[url] = None
    return sorted(seen)


def _host_of(url: str) -> Optional[str]:
    """Hostname of a URL, tolerating bare ``host`` / ``host:port`` entries."""
    parsed = urlparse(url if "://" in url else f"//{url}", scheme="http")
    return parsed.hostname


class Scanner:
    def __init__(
        self,
        ws: Workspace,
        config: Config,
        *,
        runner: Optional[CommandRunner] = None,
        registry: Optional[PluginRegistry] = None,
        on_event: Optional[EventFn] = None,
        threads: Optional[int] = None,
        use_cache: bool = False,
    ) -> None:
        self.ws = ws
        self.config = config
        self.runner = runner or CommandRunner(config)
        self.registry = registry if registry is not None else get_registry()
        self._emit: EventFn = on_event or (lambda _e: None)
        self.threads = threads or config.general.threads
        self.use_cache = use_cache

    def run(self, *, tools: Optional[list[str]] = None) -> ScanSummary:
        targets = scan_targets(self.ws)
        summary = ScanSummary(program=self.ws.program, targets=len(targets))

        chosen = scan_plugins(self.registry)
        if tools:
            wanted = {t.lower() for t in tools}
            chosen = [p for p in chosen if p.name in wanted]

        self.ws.state.start(SCAN_STATE)
        self._emit(
            {"event": "scan_start", "targets": len(targets), "tools": [p.name for p in chosen]}
        )

        # no targets: record and stop — nothing to feed the scanners
        if not targets:
            self.ws.state.skip(SCAN_STATE)
            self._emit({"event": "scan_done", "targets": 0, "findings": 0, "ran": []})
            return summary

        ctx = PluginContext(
            config=self.config,
            runner=self.runner,
            inputs=targets,
            extra={"use_cache": self.use_cache},
        )

        results: dict[str, PluginResult] = {}
        with ThreadPoolExecutor(max_workers=max(1, min(self.threads, len(chosen) or 1))) as pool:
            futures = {pool.submit(p.execute, ctx): p.name for p in chosen}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    results[name] = fut.result()
                except Exception as exc:  # a crashing scanner must not sink the run
                    results[name] = PluginResult(
                        name,
                        Capability.FINDING,
                        skipped=True,
                        reason=f"error: {exc}",
                    )

        # merge + persist on the main thread (no write races)
        for plugin in chosen:
            summary.outcomes.append(self._finalize(plugin.name, results.get(plugin.name)))

        self._write_combined(summary)
        self.ws.state.set_count("findings", summary.total_findings)
        self.ws.state.done(
            SCAN_STATE, targets=len(targets), findings=summary.total_findings, ran=summary.ran
        )
        self._emit(
            {
                "event": "scan_done",
                "targets": len(targets),
                "findings": summary.total_findings,
                "ran": summary.ran,
            }
        )
        return summary

    def _finalize(self, name: str, result: Optional[PluginResult]) -> ScanOutcome:
        if result is None or result.skipped:
            reason = result.reason if result is not None else "not run"
            self._emit({"event": "plugin_skip", "plugin": name, "reason": reason})
            return ScanOutcome(tool=name, skipped=True, reason=reason)

        findings = [f for f in result.items if f.strip()]
        self.ws.path("scans", f"{name}.txt").write_text(
            "\n".join(findings) + ("\n" if findings else ""), encoding="utf-8"
        )
        self._emit({"event": "plugin_done", "plugin": name, "found": len(findings)})
        return ScanOutcome(tool=name, findings=findings, ran=True)

    def _write_combined(self, summary: ScanSummary) -> None:
        payload = {
            "program": summary.program,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "targets": summary.targets,
            "tools": {o.tool: o.findings for o in summary.outcomes if o.ran},
        }
        self.ws.path(FINDINGS_JSON).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run_scan(
    ws: Workspace,
    config: Config,
    *,
    tools: Optional[list[str]] = None,
    runner: Optional[CommandRunner] = None,
    registry: Optional[PluginRegistry] = None,
    on_event: Optional[EventFn] = None,
    threads: Optional[int] = None,
    use_cache: bool = False,
) -> ScanSummary:
    """Convenience wrapper: build a :class:`Scanner` and run it once."""
    return Scanner(
        ws,
        config,
        runner=runner,
        registry=registry,
        on_event=on_event,
        threads=threads,
        use_cache=use_cache,
    ).run(tools=tools)
