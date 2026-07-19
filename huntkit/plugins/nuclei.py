"""nuclei — template-based vulnerability scanner (ProjectDiscovery)."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Nuclei(ToolPlugin):
    name = "nuclei"
    category = Category.SCAN
    description = "Template-based vulnerability scanner"
    install = "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    consumes = Capability.URL
    produces = Capability.FINDING
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext) -> list[str]:
        n = ctx.config.nuclei
        args = ["-silent", "-nc"]
        if n.severity:
            args += ["-severity", n.severity]
        if n.templates:
            args += ["-t", n.templates]
        if ctx.config.http.rate_limit:
            args += ["-rate-limit", str(ctx.config.http.rate_limit)]
        args += n.extra_args
        return args
