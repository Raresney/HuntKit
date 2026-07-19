"""gau — fetch known URLs from wayback/otx/commoncrawl (lc/gau)."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Gau(ToolPlugin):
    name = "gau"
    category = Category.URLS
    description = "Fetch known URLs (wayback/otx/commoncrawl)"
    install = "go install github.com/lc/gau/v2/cmd/gau@latest"
    consumes = Capability.DOMAIN
    produces = Capability.URL
    input_mode = InputMode.TARGET

    def build_args(self, ctx: PluginContext) -> list[str]:
        return ["--threads", str(ctx.config.general.threads), str(ctx.target)]
