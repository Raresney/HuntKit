"""Terminal UI layer — a one-screen engagement dashboard.

Built on Rich (already a runtime dependency); no TUI framework is added.
:func:`render_dashboard` is a pure function returning a Rich renderable, so the
view is unit-tested by rendering to a recording console and the live ``--watch``
loop is a thin wrapper around it.
"""

from __future__ import annotations

from .dashboard import render_dashboard

__all__ = ["render_dashboard"]
