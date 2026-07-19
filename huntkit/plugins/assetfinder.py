"""assetfinder — passive subdomain discovery (tomnomnom)."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Assetfinder(ToolPlugin):
    name = "assetfinder"
    category = Category.DISCOVERY
    description = "Passive subdomain discovery"
    install = "go install github.com/tomnomnom/assetfinder@latest"
    consumes = Capability.DOMAIN
    produces = Capability.SUBDOMAIN
    input_mode = InputMode.TARGET

    def build_args(self, ctx: PluginContext) -> list[str]:
        return ["--subs-only", str(ctx.target)]
