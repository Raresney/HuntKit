r"""Recon pipeline — turn a seed domain into deduped, in-scope assets.

Ties the plugin registry to a workspace and runs recon as a small dataflow:

    subs  ->  resolve  ->  live   ->  urls
                     \->  ports

Stages run in dependency **waves**; every available plugin in a wave is
executed concurrently on a thread pool, and each stage's outputs are merged
once on the main thread — so file and state writes are never touched by more
than one thread. Completed stages are recorded, letting an interrupted run
**resume** where it left off, and identical tool invocations can be served
from a content-addressed **cache**.

The public surface (:class:`Pipeline`, :func:`run_recon`) stayed stable from
phase 3; phase 4 filled in the parallelism, resume, and caching behind it.
"""

from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from .core.config import Config
from .core.runner import CommandRunner
from .core.workspace import Workspace
from .plugins import Capability, PluginContext, PluginResult, get_registry
from .plugins.registry import PluginRegistry

# Ordered recon stages and the plugins that feed each. Every *available*
# plugin in a stage runs and its output is merged, so more installed tools
# just means better coverage — no configuration required.
RECON_STAGES = ["subs", "resolve", "live", "ports", "urls"]

# Dependency waves: stages in the same wave run concurrently; a later wave
# starts only once the earlier ones finish (their output files are ready).
WAVES: list[list[str]] = [
    ["subs"],
    ["resolve"],
    ["live", "ports"],
    ["urls"],
]

STAGE_PLUGINS: dict[str, list[str]] = {
    "subs": ["subfinder", "assetfinder", "amass", "findomain", "chaos"],
    "resolve": ["dnsx"],
    "live": ["httpx"],
    "ports": ["naabu"],
    "urls": ["gau", "waybackurls", "katana", "hakrawler"],
}

STAGE_FILES: dict[str, str] = {
    "subs": "recon/subdomains.txt",
    "resolve": "recon/resolved.txt",
    "live": "recon/live.txt",
    "ports": "recon/ports.txt",
    "urls": "urls/urls.txt",
}

STAGE_COUNTS: dict[str, str] = {
    "subs": "subdomains",
    "resolve": "resolved",
    "live": "live",
    "ports": "open_ports",
    "urls": "urls",
}

# Plugins in the urls stage that walk from the seed domain rather than the
# live-host list.
_SEED_URL_PLUGINS = {"gau", "waybackurls"}

EventFn = Callable[[dict], None]


@dataclass
class StageOutcome:
    stage: str
    new: int = 0                       # newly discovered items
    total: int = 0                     # total in the file afterwards
    ran: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (plugin, reason)
    resumed: bool = False              # skipped because already done


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
        threads: Optional[int] = None,
        use_cache: bool = False,
    ) -> None:
        self.ws = ws
        self.config = config
        self.runner = runner or CommandRunner(config)
        # an empty registry is falsy (len 0), so test for None explicitly
        self.registry = registry if registry is not None else get_registry()
        self._emit: EventFn = on_event or (lambda _e: None)
        self.threads = threads or config.general.threads
        self.use_cache = use_cache

    # ---- public API ------------------------------------------------------
    def run(
        self,
        domain: str,
        stages: Optional[list[str]] = None,
        *,
        resume: bool = True,
    ) -> ReconSummary:
        wanted = set(stages or RECON_STAGES)
        summary = ReconSummary(domain=domain)
        # the seed itself is the first in-scope asset
        self.ws.append_unique(STAGE_FILES["subs"], [domain])

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            for wave in WAVES:
                active = [s for s in wave if s in wanted]
                if active:
                    self._run_wave(active, domain, pool, resume, summary)
        return summary

    # ---- one dependency wave --------------------------------------------
    def _run_wave(
        self,
        wave: list[str],
        domain: str,
        pool: ThreadPoolExecutor,
        resume: bool,
        summary: ReconSummary,
    ) -> None:
        tasks: list[tuple[str, object, PluginContext]] = []
        to_run: list[str] = []

        for stage in wave:
            if resume and self.ws.state.is_done(stage):
                self._emit({"event": "stage_resumed", "stage": stage})
                summary.stages.append(StageOutcome(
                    stage=stage, total=self.ws.count(STAGE_FILES[stage]), resumed=True,
                ))
                continue
            to_run.append(stage)
            self._emit({"event": "stage_start", "stage": stage})
            self.ws.state.start(stage)
            for name in STAGE_PLUGINS[stage]:
                plugin = self.registry.get(name)
                if plugin is None:
                    continue
                tasks.append((stage, plugin, self._context_for(stage, domain, plugin)))

        # run every plugin in the wave concurrently; collect by stage
        results: dict[str, list[tuple[str, PluginResult]]] = defaultdict(list)
        futures = {pool.submit(p.execute, ctx): (stage, p.name) for stage, p, ctx in tasks}
        for fut in as_completed(futures):
            stage, name = futures[fut]
            try:
                result = fut.result()
            except Exception as exc:  # a crashing tool must not sink the run
                result = PluginResult(name, Capability.SUBDOMAIN, skipped=True,
                                      reason=f"error: {exc}")
            results[stage].append((name, result))
            if result.skipped:
                self._emit({"event": "plugin_skip", "stage": stage,
                            "plugin": name, "reason": result.reason})
            else:
                self._emit({"event": "plugin_done", "stage": stage,
                            "plugin": name, "found": len(result.items)})

        # merge + record each stage on the main thread (no write races)
        for stage in to_run:
            summary.stages.append(self._finalize_stage(stage, results.get(stage, [])))

    # ---- merge one stage's results --------------------------------------
    def _finalize_stage(
        self, stage: str, results: list[tuple[str, PluginResult]]
    ) -> StageOutcome:
        outcome = StageOutcome(stage=stage)
        merged: list[str] = []
        for name, result in results:
            if result.skipped:
                outcome.skipped.append((name, result.reason))
                continue
            outcome.ran.append(name)
            merged.extend(self._scope_filter(stage, result.items))

        outcome.new = self.ws.append_unique(STAGE_FILES[stage], merged)

        # if nothing resolved (no dnsx, or it returned nothing), fall back to
        # the raw subdomains so live/ports still have something to work on
        fallback = False
        if stage == "resolve" and self.ws.count(STAGE_FILES["resolve"]) == 0:
            self.ws.append_unique(STAGE_FILES["resolve"],
                                  self.ws.read_lines(STAGE_FILES["subs"]))
            fallback = True

        outcome.total = self.ws.count(STAGE_FILES[stage])
        self.ws.state.set_count(STAGE_COUNTS[stage], outcome.total)
        if outcome.ran or fallback:
            self.ws.state.done(stage, new=outcome.new, total=outcome.total, fallback=fallback)
        else:
            self.ws.state.skip(stage)
        self._emit({"event": "stage_done", "stage": stage,
                    "new": outcome.new, "total": outcome.total,
                    "ran": outcome.ran, "skipped": outcome.skipped})
        return outcome

    # ---- wiring inputs per stage ----------------------------------------
    def _context_for(self, stage: str, domain: str, plugin) -> PluginContext:
        """Feed each plugin the right input for its stage."""
        target: Optional[str] = None
        inputs: list[str] = []
        if stage == "subs":
            target = domain
        elif stage == "resolve":
            inputs = self.ws.read_lines(STAGE_FILES["subs"])
        elif stage in ("live", "ports"):
            inputs = self.ws.read_lines(STAGE_FILES["resolve"])
        elif stage == "urls":
            if plugin.name in _SEED_URL_PLUGINS:
                target = domain
            else:  # crawlers walk the live hosts
                inputs = self.ws.read_lines(STAGE_FILES["live"])
        return PluginContext(
            config=self.config, runner=self.runner,
            target=target, inputs=inputs, extra={"use_cache": self.use_cache},
        )

    def _scope_filter(self, stage: str, items: list[str]) -> list[str]:
        """Keep discovered subdomains inside scope; pass other stages through.

        Later stages derive from the already-filtered subdomain set, so only
        discovery needs a scope check — defence in depth so a noisy source can
        never write an out-of-scope host to disk.
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
    resume: bool = True,
    runner: Optional[CommandRunner] = None,
    registry: Optional[PluginRegistry] = None,
    on_event: Optional[EventFn] = None,
    threads: Optional[int] = None,
    use_cache: bool = False,
) -> ReconSummary:
    """Convenience wrapper: build a :class:`Pipeline` and run it once."""
    return Pipeline(
        ws, config, runner=runner, registry=registry, on_event=on_event,
        threads=threads, use_cache=use_cache,
    ).run(domain, stages, resume=resume)
