from huntkit.core.config import Config
from huntkit.core.runner import CommandRunner
from huntkit.core.workspace import Workspace
from huntkit.pipeline import Pipeline, run_recon
from huntkit.plugins import (
    Capability,
    Category,
    InputMode,
    PluginContext,
    PluginResult,
    ToolPlugin,
)
from huntkit.plugins.registry import PluginRegistry


# --- stub plugins named to match the pipeline's stage map ------------------
class StubSubfinder(ToolPlugin):
    name = "subfinder"
    category = Category.DISCOVERY
    consumes = Capability.DOMAIN
    produces = Capability.SUBDOMAIN
    input_mode = InputMode.TARGET
    ITEMS = ["api.example.com", "www.example.com", "leak.notscope.org"]

    def build_args(self, ctx: PluginContext):
        return []

    def execute(self, ctx: PluginContext) -> PluginResult:
        return PluginResult(self.name, self.produces, items=list(self.ITEMS), ok=True)


class StubHttpx(ToolPlugin):
    name = "httpx"
    category = Category.RESOLVE
    consumes = Capability.SUBDOMAIN
    produces = Capability.URL
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext):
        return []

    def execute(self, ctx: PluginContext) -> PluginResult:
        # echo each input host back as a live https url
        return PluginResult(
            self.name, self.produces,
            items=[f"https://{h}" for h in ctx.inputs], ok=True,
        )


def _registry():
    reg = PluginRegistry()
    reg.register(StubSubfinder())
    reg.register(StubHttpx())
    return reg


def _ws(tmp_path):
    ws = Workspace.open("t", base=tmp_path)
    ws.set_scope(["*.example.com"], [])
    return ws


def test_full_chain_scope_and_dedupe(tmp_path):
    ws = _ws(tmp_path)
    cfg = Config()
    summary = run_recon(
        ws, cfg, "example.com",
        runner=CommandRunner(cfg), registry=_registry(),
    )
    subs = ws.read_lines("recon/subdomains.txt")
    # seed + two in-scope subs; the out-of-scope host is filtered out
    assert subs == ["api.example.com", "example.com", "www.example.com"]
    assert "leak.notscope.org" not in subs
    # live stage consumed the subdomains and produced urls
    live = ws.read_lines("recon/live.txt")
    assert "https://example.com" in live and len(live) == 3


def test_counts_and_state_recorded(tmp_path):
    ws = _ws(tmp_path)
    cfg = Config()
    summary = run_recon(ws, cfg, "example.com", runner=CommandRunner(cfg), registry=_registry())
    assert ws.state.is_done("subs")
    assert ws.state.is_done("live")
    assert ws.state.counts["subdomains"] == 3
    assert ws.state.counts["live"] == 3
    # stages with no available tool are marked skipped, not failed
    assert ws.state.status("ports").value == "skipped"
    subs_stage = next(s for s in summary.stages if s.stage == "subs")
    assert subs_stage.new == 2  # seed added separately; 2 new in-scope subs
    assert subs_stage.ran == ["subfinder"]


def test_stage_selection_runs_only_requested(tmp_path):
    ws = _ws(tmp_path)
    cfg = Config()
    run_recon(ws, cfg, "example.com", stages=["subs"],
              runner=CommandRunner(cfg), registry=_registry())
    assert ws.state.is_done("subs")
    # live not attempted
    assert ws.state.status("live").value == "pending"
    assert ws.read_lines("recon/live.txt") == []


def test_events_emitted(tmp_path):
    ws = _ws(tmp_path)
    cfg = Config()
    events = []
    Pipeline(
        ws, cfg, runner=CommandRunner(cfg), registry=_registry(),
        on_event=events.append,
    ).run("example.com", stages=["subs"])
    kinds = [e["event"] for e in events]
    assert "stage_start" in kinds
    assert "plugin_done" in kinds
    assert "stage_done" in kinds


def test_missing_tools_skip_gracefully(tmp_path):
    """An empty registry writes only the seed and marks stages skipped."""
    ws = _ws(tmp_path)
    cfg = Config()
    summary = run_recon(ws, cfg, "example.com",
                        runner=CommandRunner(cfg), registry=PluginRegistry())
    assert ws.read_lines("recon/subdomains.txt") == ["example.com"]  # seed only
    assert all(s.ran == [] for s in summary.stages)
