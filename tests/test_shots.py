import base64
import json

import pytest
from typer.testing import CliRunner

from huntkit.app import app
from huntkit.core.config import Config
from huntkit.core.runner import CommandRunner
from huntkit.core.workspace import Workspace
from huntkit.report import build as report_build
from huntkit.report import render
from huntkit.shots import SHOTS_DIR, run_shots, shot_targets

runner = CliRunner()

# a 1x1 transparent PNG
_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


def _ws(tmp_path, live=None, urls=None):
    ws = Workspace.open("t", base=tmp_path)
    ws.set_scope(["*.example.com"], [])
    if live:
        ws.append_unique("recon/live.txt", live)
    if urls:
        ws.append_unique("urls/urls.txt", urls)
    return ws


def _stub_capture(mapping):
    """Build a CaptureFn that writes a PNG per mapped url and returns names."""

    def capture(urls, outdir):
        for _url, name in mapping.items():
            (outdir / name).write_bytes(_PNG)
        return dict(mapping)

    return capture


# --- targets --------------------------------------------------------------
def test_shot_targets_scope_filtered(tmp_path):
    ws = _ws(
        tmp_path,
        live=["https://api.example.com"],
        urls=["https://evil.com/x", "https://blog.example.com/y"],
    )
    targets = shot_targets(ws)
    assert "https://api.example.com" in targets
    assert "https://blog.example.com/y" in targets
    assert all("evil.com" not in t for t in targets)


# --- run_shots ------------------------------------------------------------
class TestRunShots:
    def test_captures_and_writes_manifest(self, tmp_path):
        ws = _ws(tmp_path, live=["https://api.example.com", "https://www.example.com"])
        cfg = Config()
        mapping = {"https://api.example.com": "api.png", "https://www.example.com": "www.png"}
        summary = run_shots(ws, cfg, runner=CommandRunner(cfg), capture=_stub_capture(mapping))
        assert summary.targets == 2
        assert summary.captured == 2

        data = json.loads(ws.path("scans/screenshots.json").read_text())
        assert data["dir"] == SHOTS_DIR
        assert {s["url"] for s in data["shots"]} == set(mapping)
        assert all(s["file"].startswith(SHOTS_DIR) for s in data["shots"])
        assert ws.state.is_done("shots")

    def test_uncaptured_url_is_marked(self, tmp_path):
        ws = _ws(tmp_path, live=["https://api.example.com", "https://www.example.com"])
        cfg = Config()
        # only one of the two gets a shot
        summary = run_shots(
            ws,
            cfg,
            runner=CommandRunner(cfg),
            capture=_stub_capture({"https://api.example.com": "api.png"}),
        )
        assert summary.captured == 1
        missed = next(s for s in summary.shots if not s.ok)
        assert missed.error == "not captured"

    def test_no_targets_marks_skipped(self, tmp_path):
        ws = _ws(tmp_path)
        cfg = Config()
        summary = run_shots(ws, cfg, runner=CommandRunner(cfg), capture=_stub_capture({}))
        assert summary.targets == 0 and summary.captured == 0
        assert ws.state.status("shots").value == "skipped"

    def test_backend_crash_is_isolated(self, tmp_path):
        ws = _ws(tmp_path, live=["https://api.example.com"])
        cfg = Config()

        def boom(_urls, _outdir):
            raise RuntimeError("browser crashed")

        summary = run_shots(ws, cfg, runner=CommandRunner(cfg), capture=boom)
        assert summary.captured == 0
        assert ws.state.status("shots").value == "skipped"


# --- report gallery -------------------------------------------------------
def _ws_with_shots(tmp_path, entries, write_files=True):
    ws = _ws(tmp_path, live=["https://api.example.com"])
    (ws.path(SHOTS_DIR)).mkdir(parents=True, exist_ok=True)
    for e in entries:
        if write_files:
            ws.path(e["file"]).write_bytes(_PNG)
    manifest = {"program": "t", "dir": SHOTS_DIR, "shots": entries}
    ws.path("scans/screenshots.json").write_text(json.dumps(manifest))
    return ws


class TestReportGallery:
    def test_html_embeds_images_inline(self, tmp_path):
        entries = [{"url": "https://api.example.com", "file": f"{SHOTS_DIR}/api.png"}]
        ws = _ws_with_shots(tmp_path, entries)
        report = report_build(ws)
        assert len(report.screenshots) == 1
        assert report.screenshots[0].data_uri.startswith("data:image/png;base64,")

        html = render.to_html(report)
        assert "<h2>Screenshots</h2>" in html
        assert "data:image/png;base64," in html
        assert "class='gallery'" in html

    def test_markdown_lists_screenshots(self, tmp_path):
        entries = [{"url": "https://api.example.com", "file": f"{SHOTS_DIR}/api.png"}]
        ws = _ws_with_shots(tmp_path, entries)
        md = render.to_markdown(report_build(ws))
        assert "## Screenshots" in md
        assert f"[https://api.example.com]({SHOTS_DIR}/api.png)" in md

    def test_json_omits_data_uri(self, tmp_path):
        entries = [{"url": "https://api.example.com", "file": f"{SHOTS_DIR}/api.png"}]
        ws = _ws_with_shots(tmp_path, entries)
        data = report_build(ws).to_dict()
        assert data["screenshots"] == entries
        assert "data_uri" not in data["screenshots"][0]

    def test_missing_image_is_dropped_from_gallery(self, tmp_path):
        entries = [{"url": "https://api.example.com", "file": f"{SHOTS_DIR}/gone.png"}]
        ws = _ws_with_shots(tmp_path, entries, write_files=False)
        report = report_build(ws)
        # the shot is listed, but with no inlined image → not in the HTML gallery
        assert report.screenshots[0].data_uri == ""
        assert "<h2>Screenshots</h2>" not in render.to_html(report)

    def test_no_manifest_means_no_screenshots(self, tmp_path):
        ws = _ws(tmp_path, live=["https://api.example.com"])
        assert report_build(ws).screenshots == []

    def test_malformed_manifest_is_ignored(self, tmp_path):
        ws = _ws(tmp_path, live=["https://api.example.com"])
        ws.path("scans/screenshots.json").write_text("{ not json")
        assert report_build(ws).screenshots == []


# --- CLI ------------------------------------------------------------------
@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTKIT_HOME", raising=False)
    monkeypatch.setenv("HUNTKIT_GENERAL_WORKSPACE_PATH", str(tmp_path))
    monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_shots_in_help(home):
    result = runner.invoke(app, ["--help"])
    assert "shots" in result.stdout


def test_shots_needs_a_program(home):
    result = runner.invoke(app, ["shots"])
    assert result.exit_code == 2


def test_shots_no_targets_exits_cleanly(home):
    runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
    result = runner.invoke(app, ["shots", "-p", "acme"])
    assert result.exit_code == 0
    assert "no in-scope URLs" in result.stdout
