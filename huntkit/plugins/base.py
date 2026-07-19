"""The plugin contract.

Every external tool HuntKit drives is a :class:`ToolPlugin`. A plugin is a
small, declarative description of *one* binary:

  - metadata     name / category / install hint / description
  - typing       what it consumes and what it produces (a :class:`Capability`)
  - ``build_args``  turn a run context into the argv that follows the binary
  - ``parse``       turn the process output into a list of items

Everything hard — binary resolution, per-tool timeouts and extra args, proxy
environment, retries, caching — already lives in :class:`~huntkit.core.runner.
CommandRunner`. A plugin never touches subprocess; it only says *what* to run
and *how to read the result*. That is what makes adding a new tool a matter of
dropping one file into this package: the registry discovers it, the pipeline
schedules it by capability, and nothing else changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional

from ..utils.process import ProcResult

if TYPE_CHECKING:  # avoid import cycle at runtime; only needed for typing
    from ..core.config import Config
    from ..core.runner import CommandRunner


class Capability(str, Enum):
    """The data types that flow between plugins in the recon pipeline.

    A plugin ``consumes`` one type and ``produces`` another; the pipeline
    chains plugins by matching output to input (subdomains -> hosts -> urls
    -> findings) without any plugin knowing about the others.
    """

    DOMAIN = "domain"        # a seed root domain (example.com)
    SUBDOMAIN = "subdomain"  # a discovered name (api.example.com)
    HOST = "host"            # a name that resolves / is probed live
    URL = "url"              # a live http(s) endpoint
    PORT = "port"            # an open host:port
    PARAM = "param"          # a discovered request parameter
    JS = "js"                # a javascript asset
    FINDING = "finding"      # a vuln / signal worth a human's attention


class Category(str, Enum):
    """Coarse grouping for `doctor`, help output, and pipeline stages."""

    DISCOVERY = "discovery"  # find subdomains / assets
    RESOLVE = "resolve"      # probe which are live + fingerprint
    PORTS = "ports"          # port / service scanning
    URLS = "urls"            # gather / crawl urls
    SCAN = "scan"            # vuln / fuzz / param analysis
    ENRICH = "enrich"        # metadata (asn, cdn, waf, favicon, ...)


class InputMode(str, Enum):
    """How the target feeds into the tool.

    Only :data:`STDIN` is auto-wired by the base class; for the others the
    plugin places the target/inputs itself inside :meth:`ToolPlugin.build_args`,
    because flag placement differs per tool (``-d dom`` vs positional vs ``-t``).
    """

    TARGET = "target"  # a single seed placed by build_args (ctx.target)
    STDIN = "stdin"    # ctx.inputs piped to the process stdin, newline-joined
    ARGS = "args"      # ctx.inputs placed by build_args as argv
    NONE = "none"      # takes no external target


@dataclass
class PluginContext:
    """Everything a plugin needs to build and run one invocation.

    Deliberately small and decoupled: a plugin sees the config and a runner,
    a seed ``target`` (for discovery) and/or a list of ``inputs`` (for tools
    that consume the previous stage's output). ``extra`` is an escape hatch
    for one-off knobs (e.g. a FUZZ url) without growing this class.
    """

    config: "Config"
    runner: "CommandRunner"
    target: Optional[str] = None
    inputs: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


@dataclass
class PluginResult:
    """Outcome of a single plugin run."""

    plugin: str
    produces: Capability
    items: list[str] = field(default_factory=list)
    raw: Optional[ProcResult] = None
    ok: bool = False
    skipped: bool = False   # tool not installed / no input — not a failure
    reason: str = ""

    @property
    def count(self) -> int:
        return len(self.items)

    def __bool__(self) -> bool:
        return self.ok and not self.skipped


class ToolPlugin(ABC):
    """Base class for every tool integration.

    Subclasses set the class attributes and implement :meth:`build_args`.
    Override :meth:`parse` when the tool's output is not one item per line.
    The registry instantiates each concrete subclass once (they are stateless).
    """

    # ---- metadata (override as class attributes) -------------------------
    name: str = ""                       # registry key; usually the binary name
    binary: str = ""                     # executable to resolve (defaults to name)
    category: Category = Category.DISCOVERY
    description: str = ""
    install: str = ""                    # copy-pasteable install hint
    consumes: Optional[Capability] = None
    produces: Capability = Capability.SUBDOMAIN
    input_mode: InputMode = InputMode.TARGET
    needs_api_key: Optional[str] = None  # api_keys entry required, if any

    # A subclass is registrable only once it declares a name. The abstract
    # base and any intermediate helpers stay out of the registry.
    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if not getattr(cls, "binary", "") and getattr(cls, "name", ""):
            cls.binary = cls.name

    # ---- the two things a plugin must / may define -----------------------
    @abstractmethod
    def build_args(self, ctx: PluginContext) -> list[str]:
        """Return the argv that follows the binary for this invocation.

        For STDIN tools this is just the flags (input arrives via stdin);
        for TARGET/ARGS tools, place ``ctx.target`` / ``ctx.inputs`` here.
        """

    def parse(self, result: ProcResult, ctx: PluginContext) -> list[str]:
        """Extract produced items from the output. Default: one per line."""
        return result.lines

    # ---- optional hooks --------------------------------------------------
    def stdin_payload(self, ctx: PluginContext) -> Optional[str]:
        """What to pipe to stdin. Default: inputs when in STDIN mode."""
        if self.input_mode is InputMode.STDIN and ctx.inputs:
            return "\n".join(ctx.inputs)
        return None

    def cache_key(self, ctx: PluginContext) -> Optional[str]:
        """Content-addressed cache key, or None to disable caching (default)."""
        return None

    def is_available(self, runner: "CommandRunner") -> bool:
        return runner.available(self.binary)

    # ---- orchestration (do not usually override) -------------------------
    def execute(self, ctx: PluginContext) -> PluginResult:
        """Resolve, run, and parse — returning a uniform :class:`PluginResult`.

        Never raises for the ordinary "tool missing" / "empty output" cases;
        those are surfaced as ``skipped``/empty results so one gap does not
        abort a whole pipeline.
        """
        from ..core.runner import ToolNotFound

        if self.needs_api_key and not ctx.config.api_keys.get(self.needs_api_key):
            return PluginResult(self.name, self.produces, skipped=True,
                                reason=f"missing api key: {self.needs_api_key}")
        if not self.is_available(ctx.runner):
            return PluginResult(self.name, self.produces, skipped=True,
                                reason="not installed")
        if self.input_mode in (InputMode.STDIN, InputMode.ARGS) and not ctx.inputs:
            return PluginResult(self.name, self.produces, skipped=True,
                                reason="no input")

        args = self.build_args(ctx)
        try:
            result = ctx.runner.run(
                self.binary, args,
                stdin_data=self.stdin_payload(ctx),
                cache_key=self.cache_key(ctx),
            )
        except ToolNotFound as exc:
            return PluginResult(self.name, self.produces, skipped=True, reason=str(exc))

        # Non-zero exit is common (empty source); still parse what came back.
        items = self.parse(result, ctx)
        return PluginResult(
            self.name, self.produces, items=items, raw=result, ok=result.ok,
        )

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{type(self).__name__} {self.name} {self.category.value}>"
