"""waybackurls — fetch URLs from the Wayback Machine (tomnomnom).

Reads a single domain from stdin, so the seed target is piped rather than
placed on the argv.
"""

from __future__ import annotations

from typing import Optional

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Waybackurls(ToolPlugin):
    name = "waybackurls"
    category = Category.URLS
    description = "Fetch URLs from the Wayback Machine"
    install = "go install github.com/tomnomnom/waybackurls@latest"
    consumes = Capability.DOMAIN
    produces = Capability.URL
    input_mode = InputMode.TARGET  # single seed, fed via stdin below

    def build_args(self, ctx: PluginContext) -> list[str]:
        return []

    def stdin_payload(self, ctx: PluginContext) -> Optional[str]:
        if ctx.target:
            return ctx.target
        return "\n".join(ctx.inputs) if ctx.inputs else None
