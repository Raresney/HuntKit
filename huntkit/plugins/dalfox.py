"""dalfox — XSS scanning / parameter analysis (hahwul)."""

from __future__ import annotations

from ..core.pacing import Pace, delay_arg
from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Dalfox(ToolPlugin):
    name = "dalfox"
    category = Category.SCAN
    description = "XSS scanning / parameter analysis"
    install = "go install github.com/hahwul/dalfox/v2@latest"
    consumes = Capability.URL
    produces = Capability.FINDING
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext) -> list[str]:
        # pipe mode reads candidate urls from stdin
        pace = Pace.from_config(ctx.config)
        args = ["pipe", "--silence", "--no-color", "--no-spinner"]
        args += ["--worker", str(pace.concurrency)]
        args += delay_arg("--delay", pace.delay, unit="ms")  # dalfox wants ms
        return args
