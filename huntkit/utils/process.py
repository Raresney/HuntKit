"""Low-level subprocess execution.

A single, safe choke-point for running external binaries. Everything is
passed as an argv list (never a shell string) so there is no shell-injection
surface, even though HuntKit forwards user-controlled domains to tools.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Sequence


@dataclass
class ProcResult:
    """Outcome of a single command execution."""

    code: int
    stdout: str
    stderr: str
    argv: list[str]
    duration: float = 0.0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.code == 0

    @property
    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]

    def __bool__(self) -> bool:  # allow `if result:`
        return self.ok


# Sentinels for failures that never reached the binary.
NOT_FOUND = 127
TIMEOUT = 124


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def execute(
    argv: Sequence[str],
    *,
    timeout: Optional[int] = None,
    stdin_data: Optional[str] = None,
    env: Optional[dict] = None,
    cwd: Optional[str] = None,
) -> ProcResult:
    """Run `argv`, capture output, and never raise on tool failure.

    Recon tooling routinely exits non-zero (empty source, no results); that
    is data, not an error, so we surface the code and let callers decide.
    """
    import time

    argv = [str(a) for a in argv]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
    except FileNotFoundError:
        return ProcResult(NOT_FOUND, "", f"binary not found: {argv[0]}", argv,
                          duration=time.monotonic() - started)
    except subprocess.TimeoutExpired as exc:
        partial = _decode(exc.stdout)
        return ProcResult(TIMEOUT, partial, f"timeout after {timeout}s", argv,
                          duration=time.monotonic() - started, timed_out=True)
    return ProcResult(
        proc.returncode, proc.stdout, proc.stderr, argv,
        duration=time.monotonic() - started,
    )


def _decode(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode(errors="replace")
    return str(data)
