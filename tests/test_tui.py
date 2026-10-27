import json

import pytest
from rich.console import Console
from typer.testing import CliRunner

from huntkit.app import app
from huntkit.core.workspace import Workspace
from huntkit.tui import render_dashboard

runner = CliRunner()


def _seed(tmp_path) -> Workspace:
    ws = Workspace.open("acme", base=tmp_path)
    ws.append_unique(
        "recon/subdomains.txt", ["api.dev.example.com", "admin.example.com", "www.example.com"]
    )
    ws.append_unique("recon/resolved.txt", ["api.dev.example.com", "admin.example.com"])
    ws.append_unique("recon/live.txt", ["https://api.dev.example.com", "https://admin.example.com"])
    ws.append_unique("recon/ports.txt", ["admin.example.com:6379", "www.example.com:22"])
    ws.append_unique(
        "urls/urls.txt",
        [
            "https://api.dev.example.com/admin?id=5&redirect=http://x",
            "https://api.dev.example.com/.git/config",
        ],
    )
    ws.set_scope(["*.example.com"], [])
    return ws


def _text(renderable) -> str:
    con = Console(record=True, width=100, legacy_windows=False, color_system=None)
    con.print(renderable)
    return con.export_text()


class TestRender:
    def test_dashboard_shows_the_picture(self, tmp_path):
        out = _text(render_dashboard(_seed(tmp_path)))
        assert "HuntKit" in out
        assert "acme" in out
        assert "priority" in out
        assert "recon surface" in out
        assert "top hosts" in out
        assert "admin.example.com" in out
        # priority labels present
        assert "critical" in out or "high" in out
        # no snapshot baseline yet
        assert "no snapshot yet" in out

    def test_empty_workspace_renders_without_crashing(self, tmp_path):
        ws = Workspace.open("empty", base=tmp_path)
        ws.set_scope(["*.example.com"], [])
        out = _text(render_dashboard(ws))
        assert "HuntKit" in out
        assert "empty" in out
        # thin surface: no host/path tables, but it still paints
        assert "recon surface" in out

    def test_enrich_panel_appears_when_present(self, tmp_path):
        ws = _seed(tmp_path)
        manifest = {
            "favicons": [{"url": "https://admin.example.com", "hash": 12345}],
            "asns": [{"host": "admin.example.com", "asn": "13335", "prefix": "1.1.1.0/24"}],
        }
        ws.path("scans/enrich.json").write_text(json.dumps(manifest))
        out = _text(render_dashboard(ws))
        assert "enrichment" in out
        assert "favicons hashed: 1" in out
        assert "AS13335" in out

    def test_enrich_panel_absent_without_manifest(self, tmp_path):
        out = _text(render_dashboard(_seed(tmp_path)))
        assert "enrichment" not in out

    def test_snapshot_line_reflects_baseline(self, tmp_path):
        ws = _seed(tmp_path)
        # save a baseline via the history layer, then it should be referenced
        from huntkit.history import capture, save

        snap = save(ws, capture(ws))
        out = _text(render_dashboard(ws))
        assert f"last snapshot {snap.stem}" in out


# --- CLI ------------------------------------------------------------------
@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTKIT_HOME", raising=False)
    monkeypatch.setenv("HUNTKIT_GENERAL_WORKSPACE_PATH", str(tmp_path))
    monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_dashboard_in_help(home):
    result = runner.invoke(app, ["--help"])
    assert "dashboard" in result.stdout


def test_dashboard_needs_a_program(home):
    result = runner.invoke(app, ["dashboard"])
    assert result.exit_code == 2


def test_dashboard_runs(home):
    runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
    ws = Workspace.open("acme", base=home)
    ws.append_unique("recon/live.txt", ["https://admin.example.com"])
    ws.append_unique("recon/ports.txt", ["admin.example.com:6379"])
    result = runner.invoke(app, ["dashboard", "-p", "acme"])
    assert result.exit_code == 0
    assert "HuntKit" in result.stdout
