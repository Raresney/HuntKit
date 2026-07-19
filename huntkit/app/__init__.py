"""HuntKit's Typer command-line interface (v0.2).

The application object and its entry point live here. During the v0.2
transition the legacy argparse CLI (``huntkit.cli``) remains the default
``huntkit`` console script; this interface is reachable via
``python -m huntkit`` until it reaches feature parity.
"""

from __future__ import annotations

from .main import app, run

__all__ = ["app", "run"]
