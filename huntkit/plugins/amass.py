"""amass — in-depth DNS/asset enumeration (OWASP)."""

from __future__ import annotations

from ..utils import validators as v
from ..utils.process import ProcResult
from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Amass(ToolPlugin):
    name = "amass"
    category = Category.DISCOVERY
    description = "In-depth DNS/asset enumeration"
    install = "sudo apt install amass  # or go install ...owasp-amass/amass/v4/...@master"
    consumes = Capability.DOMAIN
    produces = Capability.SUBDOMAIN
    input_mode = InputMode.TARGET

    def build_args(self, ctx: PluginContext) -> list[str]:
        # passive keeps it OSINT-only (no active DNS traffic to the target)
        return ["enum", "-passive", "-nocolor", "-d", str(ctx.target)]

    def parse(self, result: ProcResult, ctx: PluginContext) -> list[str]:
        # amass interleaves progress/banner text; keep only real names
        return [ln for ln in result.lines if v.is_domain(ln)]
