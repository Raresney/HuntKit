"""Plugin discovery and lookup.

The registry is the reason a new tool costs one file: on first use it walks
this package, imports every module, and collects every concrete
:class:`~huntkit.plugins.base.ToolPlugin` subclass. Nothing has to be listed
by hand — drop ``huntkit/plugins/mytool.py`` in and it is picked up.

Consumers ask by name, category, or capability so the CLI (`doctor`, `plugins`)
and the recon pipeline can reason about tools generically.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import TYPE_CHECKING, Iterable, Optional

from .base import Capability, Category, ToolPlugin

if TYPE_CHECKING:
    from ..core.runner import CommandRunner


class PluginRegistry:
    """An in-memory index of plugin singletons, keyed by name."""

    def __init__(self) -> None:
        self._by_name: dict[str, ToolPlugin] = {}

    # ---- population ------------------------------------------------------
    def register(self, plugin: ToolPlugin) -> None:
        if not plugin.name:
            raise ValueError(f"{type(plugin).__name__} has no name")
        if plugin.name in self._by_name:
            raise ValueError(f"duplicate plugin name: {plugin.name!r}")
        self._by_name[plugin.name] = plugin

    # ---- lookup ----------------------------------------------------------
    def get(self, name: str) -> Optional[ToolPlugin]:
        return self._by_name.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._by_name

    def __len__(self) -> int:
        return len(self._by_name)

    def all(self) -> list[ToolPlugin]:
        return sorted(self._by_name.values(), key=lambda p: (p.category.value, p.name))

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def by_category(self, category: Category) -> list[ToolPlugin]:
        return [p for p in self.all() if p.category is category]

    def producing(self, cap: Capability) -> list[ToolPlugin]:
        return [p for p in self.all() if p.produces is cap]

    def consuming(self, cap: Capability) -> list[ToolPlugin]:
        return [p for p in self.all() if p.consumes is cap]

    def available(self, runner: "CommandRunner") -> list[ToolPlugin]:
        """Plugins whose binary is installed / pinned right now."""
        return [p for p in self.all() if p.is_available(runner)]

    def missing(self, runner: "CommandRunner") -> list[ToolPlugin]:
        return [p for p in self.all() if not p.is_available(runner)]


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------
def _iter_plugin_classes(package_name: str) -> Iterable[type[ToolPlugin]]:
    """Import every module in the package and yield concrete plugin classes."""
    package = importlib.import_module(package_name)
    for mod in pkgutil.iter_modules(package.__path__):
        if mod.name in {"base", "registry"} or mod.name.startswith("_"):
            continue
        importlib.import_module(f"{package_name}.{mod.name}")

    seen: set[type[ToolPlugin]] = set()
    stack: list[type[ToolPlugin]] = list(ToolPlugin.__subclasses__())
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        stack.extend(cls.__subclasses__())
        if inspect.isabstract(cls) or not getattr(cls, "name", ""):
            continue
        # only plugins that actually live in this package — never a stray
        # subclass defined by tests or downstream code
        if not cls.__module__.startswith(package_name):
            continue
        yield cls


def discover(package_name: str = __package__ or "huntkit.plugins") -> PluginRegistry:
    """Build a fresh registry by scanning ``package_name`` for plugins."""
    registry = PluginRegistry()
    for cls in _iter_plugin_classes(package_name):
        registry.register(cls())
    return registry


_REGISTRY: Optional[PluginRegistry] = None


def get_registry(*, refresh: bool = False) -> PluginRegistry:
    """Return the process-wide registry, discovering plugins on first use."""
    global _REGISTRY
    if _REGISTRY is None or refresh:
        _REGISTRY = discover()
    return _REGISTRY
