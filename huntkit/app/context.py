"""The object passed down every command via Typer's context.

Built once in the root callback from the global options, so each command
gets a ready configuration, a runner, a cache, and the plugin registry
without re-parsing anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..core.cache import Cache
from ..core.config import Config
from ..core.logger import setup_logging
from ..core.runner import CommandRunner
from ..plugins import get_registry
from ..plugins.registry import PluginRegistry


@dataclass
class AppContext:
    config: Config
    runner: CommandRunner
    cache: Cache
    registry: PluginRegistry
    base: Optional[Path] = None      # workspace base override (--workspace)

    @classmethod
    def build(
        cls,
        *,
        config_path: Optional[Path] = None,
        workspace: Optional[Path] = None,
        verbose: bool = False,
        quiet: bool = False,
    ) -> "AppContext":
        config = Config.load(config_path)
        level = "DEBUG" if verbose else ("ERROR" if quiet else "INFO")
        setup_logging(level=level, verbose=verbose)
        cache = Cache(config.workspace_root / ".cache")
        runner = CommandRunner(config, cache=cache)
        return cls(
            config=config,
            runner=runner,
            cache=cache,
            registry=get_registry(),
            base=workspace,
        )
