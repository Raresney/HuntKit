"""hakrawler — fast endpoint crawler that reads live urls from stdin."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Hakrawler(ToolPlugin):
    name = "hakrawler"
    category = Category.URLS
    description = "Crawl live hosts for endpoints and assets"
    install = "go install github.com/hakluke/hakrawler@latest"
    consumes = Capability.URL
    produces = Capability.URL
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext) -> list[str]:
        # -u unique, -d crawl depth
        return ["-u", "-d", "2"]
