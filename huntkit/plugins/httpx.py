"""httpx — probe live hosts, titles, tech, status codes (ProjectDiscovery).

Note: on a bug-bounty box this is ProjectDiscovery's ``httpx``. A Python
package of the same name ships a different ``httpx`` CLI; pin
``tools.httpx.path`` in config if both are installed.
"""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Httpx(ToolPlugin):
    name = "httpx"
    category = Category.RESOLVE
    description = "Probe live hosts (status, title, tech-detect)"
    install = "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    consumes = Capability.SUBDOMAIN
    produces = Capability.URL
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext) -> list[str]:
        args = ["-silent", "-no-color", "-t", str(ctx.config.general.threads)]
        if ctx.config.http.rate_limit:
            args += ["-rate-limit", str(ctx.config.http.rate_limit)]
        if ctx.config.http.follow_redirects:
            args.append("-follow-redirects")
        return args
