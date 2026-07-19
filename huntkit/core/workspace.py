"""Per-engagement workspace: layout, scope, deduped results, and state.

A workspace is one folder per program under the configured workspace root
(``~/.huntkit`` by default, or ``$HUNTKIT_HOME``). It owns three things:

  - **layout**   a stable set of subdirectories (recon/urls/scans/…)
  - **scope**    in/out patterns kept as plain, greppable text files, plus
                 an :meth:`in_scope` guard so nothing is scanned off-scope
  - **state**    a :class:`~huntkit.core.state.StateStore` for stage tracking,
                 counts, and resume

It sits in ``core`` because it depends only on the foundation (state, config,
utils) — never on plugins or features — so anything above can build on it.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..utils import filesystem as fs
from ..utils.validators import sanitize_filename
from .config import Config
from .state import StateStore

# Subdirectories created inside every workspace.
LAYOUT = ["scope", "recon", "urls", "scans", "notes", "reports"]

_SCOPE_IN = "scope/in_scope.txt"
_SCOPE_OUT = "scope/out_scope.txt"


def default_base(config: Config | None = None) -> Path:
    """Where workspaces live: $HUNTKIT_HOME, else config root, else ~/.huntkit."""
    env = os.environ.get("HUNTKIT_HOME")
    if env:
        return Path(env).expanduser()
    if config is not None:
        return config.workspace_root
    return Path.home() / ".huntkit"


class Workspace:
    def __init__(self, program: str, root: Path) -> None:
        self.program = program
        self.root = root
        self.state = StateStore(root / "state.json")

    # ---- construction ----------------------------------------------------
    @classmethod
    def open(
        cls,
        program: str,
        *,
        config: Config | None = None,
        base: Path | None = None,
    ) -> "Workspace":
        base = base or default_base(config)
        root = base / sanitize_filename(program)
        ws = cls(program=program, root=root)
        ws._ensure_layout()
        return ws

    def _ensure_layout(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for sub in LAYOUT:
            (self.root / sub).mkdir(exist_ok=True)
        # persist an initial state file so the workspace is discoverable by
        # `workspace list` immediately after creation
        if not self.state.path.exists():
            self.state.save()

    # ---- paths -----------------------------------------------------------
    def path(self, *parts: str) -> Path:
        """A path inside the workspace, guarded against traversal."""
        return fs.safe_join(self.root, *parts)

    # ---- scope -----------------------------------------------------------
    def set_scope(self, in_scope: list[str], out_scope: list[str]) -> None:
        fs.write_text(self.path(_SCOPE_IN), "\n".join(in_scope) + ("\n" if in_scope else ""))
        fs.write_text(self.path(_SCOPE_OUT), "\n".join(out_scope) + ("\n" if out_scope else ""))

    @property
    def scope_in(self) -> list[str]:
        return fs.read_lines(self.path(_SCOPE_IN))

    @property
    def scope_out(self) -> list[str]:
        return fs.read_lines(self.path(_SCOPE_OUT))

    def has_scope(self) -> bool:
        return bool(self.scope_in or self.scope_out)

    def in_scope(self, host: str) -> bool:
        """True if ``host`` matches an in-scope pattern and no out-of-scope one.

        Patterns accept a leading ``*.`` wildcard (``*.example.com`` matches
        the apex and any subdomain). With no in-scope patterns defined,
        everything not explicitly excluded is considered in scope.
        """
        if any(_match(host, p) for p in self.scope_out):
            return False
        ins = self.scope_in
        if not ins:
            return True
        return any(_match(host, p) for p in ins)

    def filter_scope(self, hosts: list[str]) -> list[str]:
        return [h for h in hosts if self.in_scope(h)]

    # ---- deduped result sets --------------------------------------------
    def append_unique(self, relpath: str, items: list[str]) -> int:
        """Merge items into a result file, sorted & unique; return new count."""
        return fs.append_unique(self.path(relpath), items)

    def read_lines(self, relpath: str) -> list[str]:
        return fs.read_lines(self.path(relpath))

    def count(self, relpath: str) -> int:
        return fs.count_lines(self.path(relpath))

    def exists(self, relpath: str) -> bool:
        return self.path(relpath).exists()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<Workspace {self.program} at {self.root}>"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _match(host: str, pattern: str) -> bool:
    host = host.lower().strip()
    pattern = pattern.lower().strip()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host == pattern[2:] or host.endswith(suffix)
    return host == pattern


def list_workspaces(base: Path | None = None, config: Config | None = None) -> list[str]:
    base = base or default_base(config)
    if not base.exists():
        return []
    return sorted(
        p.name for p in base.iterdir()
        if p.is_dir() and (p / "state.json").exists()
    )
