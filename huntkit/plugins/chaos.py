"""chaos — ProjectDiscovery's Chaos subdomain dataset (needs an API key)."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Chaos(ToolPlugin):
    name = "chaos"
    category = Category.DISCOVERY
    description = "Query the ProjectDiscovery Chaos dataset"
    install = "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    consumes = Capability.DOMAIN
    produces = Capability.SUBDOMAIN
    input_mode = InputMode.TARGET
    needs_api_key = "chaos"

    def build_args(self, ctx: PluginContext) -> list[str]:
        key = ctx.config.api_keys.get("chaos", "")
        return ["-d", str(ctx.target), "-silent", "-key", key]
