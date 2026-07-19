"""arjun — HTTP parameter discovery."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Arjun(ToolPlugin):
    name = "arjun"
    category = Category.SCAN
    description = "HTTP parameter discovery"
    install = "pipx install arjun  # or pip install arjun"
    consumes = Capability.URL
    produces = Capability.PARAM
    input_mode = InputMode.TARGET

    def build_args(self, ctx: PluginContext) -> list[str]:
        return ["-u", str(ctx.target), "-q"]
