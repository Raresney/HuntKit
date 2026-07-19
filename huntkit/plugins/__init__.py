"""HuntKit plugin system.

Each external tool is a self-contained :class:`ToolPlugin` in its own module.
The :func:`get_registry` singleton discovers them automatically, so extending
HuntKit is: write one file, and it is available everywhere.

    from huntkit.plugins import get_registry
    reg = get_registry()
    reg.get("subfinder")           # a plugin by name
    reg.by_category(Category.SCAN) # all vuln/fuzz plugins
    reg.available(runner)          # what is actually installed
"""

from __future__ import annotations

from .base import (
    Capability,
    Category,
    InputMode,
    PluginContext,
    PluginResult,
    ToolPlugin,
)
from .registry import PluginRegistry, discover, get_registry

__all__ = [
    "Capability",
    "Category",
    "InputMode",
    "PluginContext",
    "PluginResult",
    "ToolPlugin",
    "PluginRegistry",
    "discover",
    "get_registry",
]
