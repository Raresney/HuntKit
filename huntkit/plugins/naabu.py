"""naabu — fast SYN/CONNECT port scanner (ProjectDiscovery)."""

from __future__ import annotations

from ..core.pacing import Pace, rate_arg
from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Naabu(ToolPlugin):
    name = "naabu"
    category = Category.PORTS
    description = "Fast port scanner"
    install = "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    consumes = Capability.HOST
    produces = Capability.PORT
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext) -> list[str]:
        # hosts arrive via stdin; emit host:port on stdout. port_rate is a
        # packet budget, a different knob from the HTTP request rate.
        pace = Pace.from_config(ctx.config)
        return ["-silent", "-no-color", *rate_arg("-rate", pace.port_rate)]
