"""Recon pipeline — turn a seed domain into deduped, in-scope assets.

This is the orchestration layer that ties the plugin registry to a workspace:
run discovery, probe which hosts are live, scan ports, gather urls — writing
each stage's output to disk (sorted + unique) and recording progress in the
workspace state so nothing is repeated.

Phase 3 runs the stages sequentially; the public surface (:class:`Pipeline`,
:func:`run_recon`) is deliberately stable so phase 4 can swap the internals
for a parallel, cache-aware, resumable engine without touching callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .core.config import Config
from .core.runner import CommandRunner
from .core.workspace import Workspace
from .plugins import PluginContext, get_registry
from .plugins.registry import PluginRegistry

# Ordered recon stages and the plugins that feed each. Every *available*
# plugin in a stage is run and its output merged, so more installed tools
# simply means better coverage — no configuration required.
RECON_STAGES = ["subs", "live", "ports", "urls"]

STAGE_PLUGINS: dict[str, list[str]] = {
    "subs": ["subfinder", "assetfinder", "amass"],
    "live": ["httpx"],
    "ports": ["naabu"],
    "urls": ["gau", "katana"],
}

STAGE_FILES: dict[str, str] = {
    "subs": "recon/subdomains.txt",
    "live": "recon/live.txt",
    "ports": "recon/ports.txt",
    "urls": "urls/urls.txt",
}

STAGE_COUNTS: dict[str, str] = {
    "subs": "subdomains",
    "live": "live",
    "ports": "open_ports",
    "urls": "urls",
}

# A progress callback: receives small event dicts the CLI renders.
EventFn = Callable[[dict], None]


@dataclass
class StageOutcome:
    stage: str
    new: int = 0                       # newly discovered items
    total: int = 0                     # total in the file afterwards
    ran: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (plugin, reason)


@dataclass
class ReconSummary:
    domain: str
    stages: list[StageOutcome] = field(default_factory=list)

    @property
    def total_new(self) -> int:
        return sum(s.new for s in self.stages)


class Pipeline:
    def __init__(
        self,
        ws: Workspace,
        config: Config,
        *,
        runner: Optional[CommandRunner] = None,
        registry: Optional[PluginRegistry] = None,
        on_event: Optional[EventFn] = None,
    ) -> None:
        self.ws = ws
        self.config = config
        self.runner = runner or CommandRunner(config)
        # note: an empty registry is falsy (len 0), so test explicitly
        self.registry = registry if registry is not None else get_registry()
        self._emit: EventFn = on_event or (lambda _e: None)

    # ---- public API ------------------------------------------------------
    def run(self, domain: str, stages: Optional[list[str]] = None) -> ReconSummary:
        wanted = stages or RECON_STAGES
        summary = ReconSummary(domain=domain)
        # the seed itself is the first in-scope asset
        self.ws.append_unique(STAGE_FILES["subs"], [domain])
        for stage in RECON_STAGES:
            if stage not in wanted:
                continue
            summary.stages.append(self._run_stage(stage, domain))
        return summary

    # ---- one stage -------------------------------------------------------
    def _run_stage(self, stage: str, domain: str) -> StageOutcome:
        self._emit({"event": "stage_start", "stage": stage})
        self.ws.state.start(stage)
        outcome = StageOutcome(stage=stage)
        relpath = STAGE_FILES[stage]

        for name in STAGE_PLUGINS[stage]:
            plugin = self.registry.get(name)
            if plugin is None:
                continue
            ctx = self._context_for(stage, domain, plugin)
            result = plugin.execute(ctx)
            if result.skipped:
                outcome.skipped.append((name, result.reason))
                self._emit({"event": "plugin_skip", "stage": stage,
                            "plugin": name, "reason": result.reason})
                continue
            items = self._scope_filter(stage, result.items)
            new = self.ws.append_unique(relpath, items)
            outcome.ran.append(name)
            outcome.new += new
            self._emit({"event": "plugin_done", "stage": stage, "plugin": name,
                        "found": len(items), "new": new})

        outcome.total = self.ws.count(relpath)
        self.ws.state.set_count(STAGE_COUNTS[stage], outcome.total)
        if outcome.ran:
            self.ws.state.done(stage, new=outcome.new, total=outcome.total)
        else:
            self.ws.state.skip(stage)
        self._emit({"event": "stage_done", "stage": stage,
                    "new": outcome.new, "total": outcome.total,
                    "ran": outcome.ran, "skipped": outcome.skipped})
        return outcome

    # ---- wiring inputs per stage ----------------------------------------
    def _context_for(self, stage: str, domain: str, plugin) -> PluginContext:
        """Feed each plugin the right input for its stage.

        Discovery and gau take the seed as a target; live/ports/katana
        consume the previous stage's file as an input list.
        """
        target: Optional[str] = None
        inputs: list[str] = []
        if stage == "subs":
            target = domain
        elif stage == "live":
            inputs = self.ws.read_lines(STAGE_FILES["subs"])
        elif stage == "ports":
            inputs = self.ws.read_lines(STAGE_FILES["subs"])
        elif stage == "urls":
            if plugin.name == "katana":
                inputs = self.ws.read_lines(STAGE_FILES["live"])
            else:  # gau and friends walk from the seed domain
                target = domain
        return PluginContext(
            config=self.config, runner=self.runner, target=target, inputs=inputs,
        )

    def _scope_filter(self, stage: str, items: list[str]) -> list[str]:
        """Keep discovered subdomains inside scope; pass other stages through.

        Later stages derive from the already-filtered subdomain set, so only
        discovery needs a scope check — a defence-in-depth guard so a noisy
        source can never write an out-of-scope host to disk.
        """
        if stage != "subs":
            return items
        return self.ws.filter_scope(items)


def run_recon(
    ws: Workspace,
    config: Config,
    domain: str,
    *,
    stages: Optional[list[str]] = None,
    runner: Optional[CommandRunner] = None,
    registry: Optional[PluginRegistry] = None,
    on_event: Optional[EventFn] = None,
) -> ReconSummary:
    """Convenience wrapper: build a :class:`Pipeline` and run it once."""
    return Pipeline(
        ws, config, runner=runner, registry=registry, on_event=on_event
    ).run(domain, stages)
