import json

import pytest
from typer.testing import CliRunner

from huntkit.app import app
from huntkit.core.workspace import Workspace
from huntkit.history import (
    Snapshot,
    capture,
    current_vs,
    diff_snapshots,
    find,
    latest,
    list_snapshots,
    load,
    save,
)

runner = CliRunner()


def _ws(tmp_path, *, subs=None, live=None, urls=None, findings=None):
    ws = Workspace.open("t", base=tmp_path)
    ws.set_scope(["*.example.com"], [])
    if subs:
        ws.append_unique("recon/subdomains.txt", subs)
    if live:
        ws.append_unique("recon/live.txt", live)
    if urls:
        ws.append_unique("urls/urls.txt", urls)
    if findings:
        ws.path("scans/findings.json").write_text(json.dumps({"tools": findings}))
    return ws


# --- capture --------------------------------------------------------------
class TestCapture:
    def test_captures_files_and_findings(self, tmp_path):
        ws = _ws(
            tmp_path,
            subs=["a.example.com", "b.example.com"],
            live=["https://a.example.com"],
            findings={"nuclei": ["https://a.example.com [cve] x"], "dalfox": ["xss-hit"]},
        )
        snap = capture(ws)
        assert snap.get("subdomains") == ["a.example.com", "b.example.com"]
        assert snap.get("live") == ["https://a.example.com"]
        assert snap.get("findings") == ["https://a.example.com [cve] x", "xss-hit"]
        assert snap.counts["subdomains"] == 2

    def test_dedupes_and_sorts(self, tmp_path):
        ws = _ws(tmp_path, subs=["b.example.com", "a.example.com", "a.example.com"])
        assert capture(ws).get("subdomains") == ["a.example.com", "b.example.com"]

    def test_missing_findings_json_is_empty(self, tmp_path):
        ws = _ws(tmp_path, live=["https://a.example.com"])
        assert capture(ws).get("findings") == []

    def test_malformed_findings_json_ignored(self, tmp_path):
        ws = _ws(tmp_path, live=["https://a.example.com"])
        ws.path("scans/findings.json").write_text("{ not json")
        assert capture(ws).get("findings") == []


# --- store roundtrip ------------------------------------------------------
class TestStore:
    def test_save_load_roundtrip(self, tmp_path):
        ws = _ws(tmp_path, subs=["a.example.com"])
        snap = capture(ws)
        path = save(ws, snap)
        assert path.exists()
        back = load(path)
        assert back.id == snap.id
        assert back.get("subdomains") == ["a.example.com"]

    def test_latest_find_list(self, tmp_path):
        ws = _ws(tmp_path, subs=["a.example.com"])
        s1 = Snapshot(id="20260101-000000", generated="t1", items={"subdomains": ["a.example.com"]})
        s2 = Snapshot(id="20260202-000000", generated="t2", items={"subdomains": ["b.example.com"]})
        save(ws, s1)
        save(ws, s2)
        assert [s.id for s in list_snapshots(ws)] == ["20260101-000000", "20260202-000000"]
        assert latest(ws).id == "20260202-000000"
        assert find(ws, "20260101-000000").get("subdomains") == ["a.example.com"]
        assert find(ws, "nope") is None


# --- diff -----------------------------------------------------------------
class TestDiff:
    def test_added_and_removed(self, tmp_path):
        old = Snapshot("o", "t0", {"subdomains": ["a.example.com", "b.example.com"]})
        new = Snapshot("n", "t1", {"subdomains": ["b.example.com", "c.example.com"]})
        report = diff_snapshots(old, new, "t")
        subs = report.by_name("subdomains")
        assert subs.added == ["c.example.com"]
        assert subs.removed == ["a.example.com"]
        assert report.total_added == 1 and report.total_removed == 1
        assert report.has_changes

    def test_new_findings_surface(self, tmp_path):
        old = Snapshot("o", "t0", {"findings": ["old-hit"]})
        new = Snapshot("n", "t1", {"findings": ["old-hit", "NEW-critical-hit"]})
        report = diff_snapshots(old, new, "t")
        assert report.new_findings == ["NEW-critical-hit"]

    def test_no_change(self, tmp_path):
        snap = Snapshot("o", "t0", {"live": ["https://a.example.com"]})
        report = diff_snapshots(snap, snap, "t")
        assert not report.has_changes
        assert report.changed == []

    def test_current_vs_baseline(self, tmp_path):
        ws = _ws(tmp_path, live=["https://a.example.com"])
        baseline = save(ws, capture(ws))
        # a new host goes live after the baseline
        ws.append_unique("recon/live.txt", ["https://new.example.com"])
        report, now = current_vs(ws, load(baseline))
        assert report.by_name("live").added == ["https://new.example.com"]
        assert "https://new.example.com" in now.get("live")


# --- CLI ------------------------------------------------------------------
@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTKIT_HOME", raising=False)
    monkeypatch.setenv("HUNTKIT_GENERAL_WORKSPACE_PATH", str(tmp_path))
    monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _seed_live(home, host):
    ws = Workspace.open("acme", base=home)
    ws.append_unique("recon/live.txt", [host])


def test_diff_in_help(home):
    result = runner.invoke(app, ["--help"])
    assert "diff" in result.stdout


def test_diff_needs_a_program(home):
    result = runner.invoke(app, ["diff"])
    assert result.exit_code == 2


def test_diff_no_baseline_warns(home):
    runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
    result = runner.invoke(app, ["diff", "-p", "acme"])
    assert result.exit_code == 0
    assert "no baseline" in result.stdout


def test_diff_save_then_detect_change(home):
    runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
    _seed_live(home, "https://a.example.com")
    r1 = runner.invoke(app, ["diff", "-p", "acme", "--save"])
    assert r1.exit_code == 0 and "saved" in r1.stdout.lower()

    _seed_live(home, "https://b.example.com")
    r2 = runner.invoke(app, ["diff", "-p", "acme"])
    assert r2.exit_code == 0
    assert "+1" in r2.stdout
    assert "b.example.com" in r2.stdout


def test_diff_list(home):
    runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
    _seed_live(home, "https://a.example.com")
    runner.invoke(app, ["diff", "-p", "acme", "--save"])
    result = runner.invoke(app, ["diff", "-p", "acme", "--list"])
    assert result.exit_code == 0
    assert "Saved snapshots" in result.stdout


def test_diff_unknown_baseline_errors(home):
    runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
    result = runner.invoke(app, ["diff", "-p", "acme", "--against", "nope"])
    assert result.exit_code == 2
