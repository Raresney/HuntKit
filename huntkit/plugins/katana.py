"""katana — active crawler / URL discovery (ProjectDiscovery)."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Katana(ToolPlugin):
    name = "katana"
    category = Category.URLS
    description = "Active crawler / URL discovery"
    install = "go install github.com/projectdiscovery/katana/cmd/katana@latest"
    consumes = Capability.URL
    produces = Capability.URL
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext) -> list[str]:
        # urls arrive via stdin; -d = crawl depth, -c = concurrency
        return ["-silent", "-nc", "-d", "2", "-c", str(ctx.config.general.threads)]
