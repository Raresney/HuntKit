"""dnsx — fast DNS resolver; filters a name list down to what resolves."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Dnsx(ToolPlugin):
    name = "dnsx"
    category = Category.RESOLVE
    description = "Resolve a subdomain list, keeping only live DNS names"
    install = "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    consumes = Capability.SUBDOMAIN
    produces = Capability.HOST
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext) -> list[str]:
        return ["-silent", "-nc"]
