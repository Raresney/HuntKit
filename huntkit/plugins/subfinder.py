"""subfinder — passive subdomain enumeration (ProjectDiscovery)."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Subfinder(ToolPlugin):
    name = "subfinder"
    category = Category.DISCOVERY
    description = "Passive subdomain enumeration"
    install = "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    consumes = Capability.DOMAIN
    produces = Capability.SUBDOMAIN
    input_mode = InputMode.TARGET

    def build_args(self, ctx: PluginContext) -> list[str]:
        return ["-silent", "-d", str(ctx.target)]
