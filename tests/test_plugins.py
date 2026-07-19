import sys

import pytest

from huntkit.core.config import Config
from huntkit.core.runner import CommandRunner
from huntkit.plugins import (
    Capability,
    Category,
    InputMode,
    PluginContext,
    ToolPlugin,
    discover,
    get_registry,
)
from huntkit.plugins.amass import Amass
from huntkit.plugins.nmap import Nmap
from huntkit.utils.process import ProcResult

EXPECTED = {
    "subfinder", "assetfinder", "amass", "findomain", "chaos",  # discovery
    "httpx", "whatweb", "dnsx",                                  # resolve
    "naabu", "nmap",                                             # ports
    "gau", "waybackurls", "katana", "hakrawler",                # urls
    "nuclei", "ffuf", "arjun", "dalfox",                        # scan
}


def _ctx(target=None, inputs=None, cfg=None, runner=None, **extra):
    cfg = cfg or Config()
    return PluginContext(
        config=cfg,
        runner=runner or CommandRunner(cfg),
        target=target,
        inputs=inputs or [],
        extra=extra,
    )


def _runner_pinning(binary, argv_path):
    """A runner whose `binary` resolves to a real executable for a live run."""
    cfg = Config.from_dict({"tools": {binary: {"path": argv_path}}})
    return CommandRunner(cfg)


class TestDiscovery:
    def test_all_known_tools_present(self):
        reg = discover()
        assert set(reg.names()) == EXPECTED

    def test_no_duplicates_and_singleton(self):
        assert len(discover()) == len(EXPECTED)
        assert get_registry() is get_registry()  # cached

    def test_lookup_helpers(self):
        reg = discover()
        assert reg.get("subfinder").category is Category.DISCOVERY
        assert reg.get("nope") is None
        assert "nuclei" in reg
        assert {p.name for p in reg.by_category(Category.SCAN)} == {
            "nuclei", "ffuf", "arjun", "dalfox"
        }
        assert "httpx" in {p.name for p in reg.producing(Capability.URL)}
        assert "nuclei" in {p.name for p in reg.consuming(Capability.URL)}

    def test_metadata_is_complete(self):
        for p in discover().all():
            assert p.name and p.binary == p.name
            assert p.install, f"{p.name} lacks an install hint"
            assert isinstance(p.produces, Capability)
            assert isinstance(p.category, Category)

    def test_capability_chain_is_wired(self):
        """subdomains -> live urls -> scanned: each stage feeds the next."""
        reg = discover()
        assert reg.producing(Capability.SUBDOMAIN)          # discovery exists
        assert reg.consuming(Capability.SUBDOMAIN)          # httpx takes them
        assert reg.producing(Capability.URL)                # urls produced
        assert reg.consuming(Capability.URL)                # scanners take them


class TestBuildArgs:
    def test_target_mode_places_seed(self):
        reg = discover()
        assert reg.get("subfinder").build_args(_ctx(target="x.com")) == [
            "-silent", "-d", "x.com"
        ]
        assert reg.get("assetfinder").build_args(_ctx(target="x.com")) == [
            "--subs-only", "x.com"
        ]

    def test_stdin_mode_flags_only(self):
        # input goes via stdin, so args carry no hosts
        args = discover().get("httpx").build_args(_ctx(inputs=["a.x.com"]))
        assert "-silent" in args and "a.x.com" not in args

    def test_args_mode_appends_inputs(self):
        args = Nmap().build_args(_ctx(inputs=["1.2.3.4", "5.6.7.8"]))
        assert args[-2:] == ["1.2.3.4", "5.6.7.8"]
        assert "-oG" in args

    def test_nuclei_pulls_config(self):
        cfg = Config.from_dict({"nuclei": {"severity": "critical", "templates": "/t"}})
        args = discover().get("nuclei").build_args(_ctx(cfg=cfg))
        assert "critical" in args and "/t" in args

    def test_ffuf_adds_fuzz_marker_and_wordlist(self):
        args = discover().get("ffuf").build_args(_ctx(target="https://x.com", wordlist="/wl"))
        assert "https://x.com/FUZZ" in args
        assert "/wl" in args


class TestParse:
    def test_nmap_greppable_parse(self):
        sample = (
            "# Nmap 7.94 scan\n"
            "Host: 1.2.3.4 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///, "
            "443/closed/tcp//https///\n"
            "# Nmap done\n"
        )
        out = Nmap().parse(ProcResult(0, sample, "", []), _ctx())
        assert out == ["1.2.3.4:22", "1.2.3.4:80"]  # closed dropped

    def test_amass_filters_non_domains(self):
        sample = "[*] querying sources...\napi.x.com\nnot a domain\nwww.x.com\n"
        out = Amass().parse(ProcResult(0, sample, "", []), _ctx())
        assert out == ["api.x.com", "www.x.com"]

    def test_default_parse_is_lines(self):
        out = discover().get("subfinder").parse(
            ProcResult(0, "a.x.com\n\nb.x.com\n", "", []), _ctx()
        )
        assert out == ["a.x.com", "b.x.com"]


class TestExecute:
    def test_skips_when_not_installed(self):
        # a tool that certainly is not on PATH
        p = discover().get("subfinder")
        runner = CommandRunner(Config())  # subfinder not pinned, not installed here
        res = p.execute(_ctx(target="x.com", runner=runner))
        if not runner.available("subfinder"):
            assert res.skipped and res.reason == "not installed"
            assert not res

    def test_skips_stdin_tool_with_no_input(self):
        p = discover().get("httpx")
        # pin so availability is not the reason it skips
        runner = _runner_pinning("httpx", sys.executable)
        res = p.execute(_ctx(inputs=[], runner=runner))
        assert res.skipped and res.reason == "no input"

    def test_api_key_gate(self):
        class Keyed(ToolPlugin):
            name = "keyed_probe"
            input_mode = InputMode.TARGET
            needs_api_key = "shodan"

            def build_args(self, ctx):
                return []

        res = Keyed().execute(_ctx(target="x.com"))
        assert res.skipped and "api key" in res.reason

    def test_full_run_through_stdin(self):
        """End-to-end: pin the binary to python, feed stdin, parse output."""

        class Echo(ToolPlugin):
            name = "echo_probe"
            input_mode = InputMode.STDIN
            produces = Capability.URL

            def build_args(self, ctx):
                return ["-c", "import sys; print(sys.stdin.read().strip().upper())"]

        runner = _runner_pinning("echo_probe", sys.executable)
        res = Echo().execute(_ctx(inputs=["a.com"], runner=runner))
        assert res.ok and not res.skipped
        assert res.items == ["A.COM"]
        assert res.count == 1
        assert bool(res) is True


class TestCaching:
    def test_cache_key_is_opt_in(self):
        p = discover().get("subfinder")
        assert p.cache_key(_ctx(target="x.com")) is None  # off by default
        key = p.cache_key(_ctx(target="x.com", use_cache=True))
        assert key
        # stable for identical invocation, distinct for a different target
        assert p.cache_key(_ctx(target="x.com", use_cache=True)) == key
        assert p.cache_key(_ctx(target="y.com", use_cache=True)) != key


class TestApiKeyPlugins:
    def test_chaos_needs_key_and_passes_it(self):
        p = discover().get("chaos")
        assert p.needs_api_key == "chaos"
        cfg = Config.from_dict({"api_keys": {"chaos": "secret"}})
        args = p.build_args(_ctx(target="x.com", cfg=cfg))
        assert "secret" in args and "x.com" in args


def test_registry_rejects_duplicate():
    from huntkit.plugins.registry import PluginRegistry

    reg = PluginRegistry()
    reg.register(discover().get("subfinder"))
    with pytest.raises(ValueError):
        reg.register(discover().get("subfinder"))
