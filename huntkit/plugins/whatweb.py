"""whatweb — technology fingerprinting."""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class WhatWeb(ToolPlugin):
    name = "whatweb"
    category = Category.RESOLVE
    description = "Technology fingerprinting"
    install = "sudo apt install whatweb"
    consumes = Capability.URL
    produces = Capability.FINDING
    input_mode = InputMode.ARGS

    def build_args(self, ctx: PluginContext) -> list[str]:
        # one fingerprint line per target; targets given as argv
        return ["--no-errors", "--colour=never", "-q", *ctx.inputs]
