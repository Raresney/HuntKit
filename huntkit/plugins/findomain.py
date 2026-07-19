"""findomain — fast passive subdomain enumeration."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Findomain(ToolPlugin):
    name = "findomain"
    category = Category.DISCOVERY
    description = "Fast passive subdomain enumeration"
    install = "sudo apt install findomain  # or grab a release binary"
    consumes = Capability.DOMAIN
    produces = Capability.SUBDOMAIN
    input_mode = InputMode.TARGET

    def build_args(self, ctx: PluginContext) -> list[str]:
        return ["-t", str(ctx.target), "-q"]
