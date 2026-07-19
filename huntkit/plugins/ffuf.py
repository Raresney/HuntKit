"""ffuf — content/vhost/parameter fuzzing.

Needs a URL containing the ``FUZZ`` marker and a wordlist. If the target has
no marker, ``/FUZZ`` is appended; the wordlist comes from ``ctx.extra`` or
``wordlists.dir_fuzz`` in config.
"""

from __future__ import annotations

from .base import Capability, Category, InputMode, PluginContext, ToolPlugin


class Ffuf(ToolPlugin):
    name = "ffuf"
    category = Category.SCAN
    description = "Content/vhost/parameter fuzzing"
    install = "go install github.com/ffuf/ffuf/v2@latest"
    consumes = Capability.URL
    produces = Capability.URL
    input_mode = InputMode.TARGET

    def build_args(self, ctx: PluginContext) -> list[str]:
        url = str(ctx.target or "")
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        args = ["-u", url, "-s", "-mc", "200,204,301,302,307,401,403"]
        wordlist = ctx.extra.get("wordlist") or ctx.config.wordlists.dir_fuzz
        if wordlist:
            args += ["-w", str(wordlist)]
        return args
