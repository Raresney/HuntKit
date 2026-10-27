import json

import pytest
from typer.testing import CliRunner

from huntkit.app import app
from huntkit.core.config import Config
from huntkit.core.runner import CommandRunner
from huntkit.core.workspace import Workspace
from huntkit.plugins import (
    Capability,
    Category,
    InputMode,
    PluginContext,
    PluginResult,
    ToolPlugin,
)
from huntkit.plugins.registry import PluginRegistry
from huntkit.scanner import run_scan, scan_targets

runner = CliRunner()


# --- stub scanners (SCAN category, stdin) ---------------------------------
class StubNuclei(ToolPlugin):
    name = "nuclei"
    category = Category.SCAN
    consumes = Capability.URL
    produces = Capability.FINDING
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext):
        return []

    def execute(self, ctx: PluginContext) -> PluginResult:
        # one "finding" per candidate url
        items = [f"{u} [CVE-0000] exposure" for u in ctx.inputs]
        return PluginResult(self.name, self.produces, items=items, ok=True)


class StubDalfox(ToolPlugin):
    name = "dalfox"
    category = Category.SCAN
    consumes = Capability.URL
    produces = Capability.FINDING
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext):
        return []

    def execute(self, ctx: PluginContext) -> PluginResult:
        return PluginResult(self.name, self.produces, items=["one-xss-hit"], ok=True)


class CrashingScanner(ToolPlugin):
    name = "nuclei"
    category = Category.SCAN
    consumes = Capability.URL
    produces = Capability.FINDING
    input_mode = InputMode.STDIN

    def build_args(self, ctx: PluginContext):
        return []

    def execute(self, ctx: PluginContext) -> PluginResult:
        raise RuntimeError("boom")


def _ws(tmp_path, live=None, urls=None):
    ws = Workspace.open("t", base=tmp_path)
    ws.set_scope(["*.example.com"], [])
    if live:
        ws.append_unique("recon/live.txt", live)
    if urls:
        ws.append_unique("urls/urls.txt", urls)
    return ws


def _registry(*plugins):
    reg = PluginRegistry()
    for p in plugins:
        reg.register(p)
    return reg


def test_scan_runs_over_targets_and_writes_files(tmp_path):
    ws = _ws(tmp_path, live=["https://api.example.com", "https://www.example.com"])
    cfg = Config()
    summary = run_scan(
        ws,
        cfg,
        runner=CommandRunner(cfg),
        registry=_registry(StubNuclei(), StubDalfox()),
    )
    assert summary.targets == 2
    # nuclei found one per target, dalfox one
    assert summary.total_findings == 3
    assert set(summary.ran) == {"nuclei", "dalfox"}

    # per-tool raw output written
    assert ws.exists("scans/nuclei.txt")
    nuclei_lines = ws.read_lines("scans/nuclei.txt")
    assert len(nuclei_lines) == 2

    # combined json written with both tools
    data = json.loads(ws.path("scans/findings.json").read_text())
    assert data["targets"] == 2
    assert set(data["tools"]) == {"nuclei", "dalfox"}
    assert ws.state.counts["findings"] == 3
    assert ws.state.is_done("scan")


def test_scan_scope_filters_out_of_scope_urls(tmp_path):
    ws = _ws(
        tmp_path,
        live=["https://api.example.com"],
        urls=["https://evil.com/x", "https://blog.example.com/y"],
    )
    targets = scan_targets(ws)
    assert "https://evil.com/x" not in targets
    assert "https://api.example.com" in targets
    assert "https://blog.example.com/y" in targets


def test_scan_no_targets_marks_skipped(tmp_path):
    ws = _ws(tmp_path)  # nothing gathered
    cfg = Config()
    summary = run_scan(ws, cfg, runner=CommandRunner(cfg), registry=_registry(StubNuclei()))
    assert summary.targets == 0
    assert summary.total_findings == 0
    assert ws.state.status("scan").value == "skipped"


def test_scan_tool_selection(tmp_path):
    ws = _ws(tmp_path, live=["https://api.example.com"])
    cfg = Config()
    summary = run_scan(
        ws,
        cfg,
        runner=CommandRunner(cfg),
        registry=_registry(StubNuclei(), StubDalfox()),
        tools=["dalfox"],
    )
    assert summary.ran == ["dalfox"]
    assert not ws.exists("scans/nuclei.txt")


def test_scan_empty_registry_runs_nothing(tmp_path):
    ws = _ws(tmp_path, live=["https://api.example.com"])
    cfg = Config()
    summary = run_scan(ws, cfg, runner=CommandRunner(cfg), registry=PluginRegistry())
    assert summary.targets == 1
    assert summary.ran == []
    assert summary.total_findings == 0


def test_scan_crashing_scanner_is_isolated(tmp_path):
    ws = _ws(tmp_path, live=["https://api.example.com"])
    cfg = Config()
    summary = run_scan(
        ws,
        cfg,
        runner=CommandRunner(cfg),
        registry=_registry(CrashingScanner()),
    )
    # the crash is captured as a skip, not raised
    assert summary.ran == []
    crashed = next(o for o in summary.outcomes if o.tool == "nuclei")
    assert crashed.skipped and "boom" in crashed.reason


# --- CLI ------------------------------------------------------------------
@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTKIT_HOME", raising=False)
    monkeypatch.setenv("HUNTKIT_GENERAL_WORKSPACE_PATH", str(tmp_path))
    monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_scan_in_help(home):
    result = runner.invoke(app, ["--help"])
    assert "scan" in result.stdout


def test_scan_no_targets_exits_cleanly(home):
    runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
    result = runner.invoke(app, ["scan", "-p", "acme"])
    assert result.exit_code == 0
    assert "no in-scope URLs" in result.stdout


def test_scan_needs_a_program(home):
    # no workspace exists yet -> cannot infer one
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 2
