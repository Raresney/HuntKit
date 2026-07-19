"""CommandRunner — the configured, logged execution layer.

Sits on top of `utils.process.execute` and adds everything a plugin should
not have to think about: binary resolution, per-tool timeouts and extra
args, proxy/UA environment, retries with backoff, structured logging, and
optional result caching.

Plugins build an argv and hand it here; they never call subprocess directly.
"""

from __future__ import annotations

import time
from typing import Optional, Sequence

from ..utils import process
from ..utils.process import ProcResult
from .config import Config
from .logger import get_logger

log = get_logger("runner")


class ToolNotFound(RuntimeError):
    """Raised when a required binary is not on PATH and not pinned in config."""


class CommandRunner:
    def __init__(self, config: Optional[Config] = None, cache=None) -> None:
        self.config = config or Config()
        self.cache = cache  # optional core.cache.Cache; injected by the app

    # ---- binary resolution ----------------------------------------------
    def resolve(self, tool: str) -> Optional[str]:
        """Return the binary path for `tool`, honouring a pinned config path."""
        pinned = self.config.tool(tool).path
        if pinned:
            return pinned
        return process.which(tool)

    def available(self, tool: str) -> bool:
        return self.resolve(tool) is not None

    # ---- execution -------------------------------------------------------
    def run(
        self,
        tool: str,
        args: Sequence[str],
        *,
        stdin_data: Optional[str] = None,
        timeout: Optional[int] = None,
        retry: Optional[int] = None,
        cache_key: Optional[str] = None,
    ) -> ProcResult:
        """Run a registered tool with `args`.

        `tool` is the binary name (resolved via config/PATH); `args` are the
        arguments after it. Per-tool `extra_args` from config are appended.
        """
        binary = self.resolve(tool)
        if binary is None:
            raise ToolNotFound(
                f"'{tool}' not found on PATH — install it or set tools.{tool}.path"
            )

        tool_cfg = self.config.tool(tool)
        argv = [binary, *[str(a) for a in args], *tool_cfg.extra_args]
        eff_timeout = timeout or tool_cfg.timeout or self.config.general.timeout
        eff_retry = self.config.general.retry if retry is None else retry

        if cache_key and self.cache is not None:
            cached = self.cache.get(cache_key)
            if cached is not None:
                log.debug("cache hit: %s", cache_key)
                return ProcResult(0, cached, "", argv, timed_out=False)

        result = self._run_with_retry(argv, stdin_data, eff_timeout, eff_retry, tool)

        if cache_key and self.cache is not None and result.ok:
            self.cache.set(cache_key, result.stdout)
        return result

    def _run_with_retry(
        self,
        argv: list[str],
        stdin_data: Optional[str],
        timeout: int,
        retry: int,
        tool: str,
    ) -> ProcResult:
        env = self._build_env()
        last: Optional[ProcResult] = None
        for attempt in range(retry + 1):
            log.debug("exec (try %d/%d): %s", attempt + 1, retry + 1, " ".join(argv))
            result = process.execute(argv, timeout=timeout, stdin_data=stdin_data, env=env)
            log.debug("→ code=%s dur=%.1fs lines=%d", result.code, result.duration,
                      len(result.lines))
            # retry only transient failures (timeout), not clean non-zero exits
            if result.ok or not result.timed_out or attempt == retry:
                return result
            last = result
            backoff = 1.5 * (attempt + 1)
            log.warning("%s timed out; retrying in %.1fs", tool, backoff)
            time.sleep(backoff)
        return last or process.execute(argv, timeout=timeout, stdin_data=stdin_data, env=env)

    def _build_env(self) -> Optional[dict]:
        """Inject proxy/UA into the child environment when configured."""
        import os

        http = self.config.http
        if not http.proxy:
            return None
        env = dict(os.environ)
        env["HTTP_PROXY"] = http.proxy
        env["HTTPS_PROXY"] = http.proxy
        return env
