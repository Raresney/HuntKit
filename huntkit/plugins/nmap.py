"""nmap — port scan + service/version detection.

Reads targets as argv (nmap has no stdin list mode) and emits greppable
output on stdout, which we parse into ``host:port`` entries.
"""

from __future__ import annotations

from ..utils.process import ProcResult
from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Nmap(ToolPlugin):
    name = "nmap"
    category = Category.PORTS
    description = "Port scan + service/version detection"
    install = "sudo apt install nmap"
    consumes = Capability.HOST
    produces = Capability.PORT
    input_mode = InputMode.ARGS

    def build_args(self, ctx: PluginContext) -> list[str]:
        return ["-T4", "-Pn", "--top-ports", "1000", "-oG", "-", *ctx.inputs]

    def parse(self, result: ProcResult, ctx: PluginContext) -> list[str]:
        out: list[str] = []
        for line in result.lines:
            if "Ports:" not in line:
                continue
            parts = line.split()
            if len(parts) < 2 or parts[0] != "Host:":
                continue
            host = parts[1]
            # e.g. "Ports: 22/open/tcp//ssh///, 80/open/tcp//http///"
            for chunk in line.split("Ports:", 1)[1].split(","):
                fields = chunk.strip().split("/")
                if len(fields) >= 2 and fields[1] == "open":
                    out.append(f"{host}:{fields[0]}")
        return out
