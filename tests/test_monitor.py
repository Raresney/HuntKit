"""Monitor orchestration — baseline, diff, notify. Recon & POST injected."""

from __future__ import annotations

import json

from huntkit.core.config import Config
from huntkit.core.workspace import Workspace
from huntkit.history import capture, latest, list_snapshots, save
from huntkit.monitor import NOTIFY_CHANGES, run_monitor
from huntkit.pipeline import ReconSummary


def _ws(tmp_path, *, subs=None, findings=None):
    ws = Workspace.open("t", base=tmp_path)
    ws.set_scope(["*.example.com"], [])
    if subs:
        ws.append_unique("recon/subdomains.txt", subs)
    if findings:
        ws.path("scans/findings.json").write_text(json.dumps({"tools": findings}))
    return ws


def _recon_noop():
    # monitor re-runs recon; tests inject a no-op that touches no network.
    return ReconSummary(domain="example.com")


class TestFirstRun:
    def test_saves_baseline_and_never_notifies(self, tmp_path):
        ws = _ws(tmp_path, subs=["a.example.com"])
        posts = []
        result = run_monitor(
            ws,
            Config(),
            "example.com",
            webhook="https://hooks.slack.com/x",
            recon=_recon_noop,
            post=lambda u, p: posts.append((u, p)) or True,
        )
        assert result.first_run is True
        assert result.report is None
        assert result.notified is False
        assert posts == []
        # the baseline is now on disk
        assert len(list_snapshots(ws)) == 1
        assert latest(ws).id == result.snapshot.id


class TestDelta:
    def test_new_finding_fires_webhook(self, tmp_path):
        ws = _ws(tmp_path, subs=["a.example.com"])
        save(ws, capture(ws))  # establish a baseline

        # a finding appears before the next sweep
        ws.path("scans/findings.json").write_text(json.dumps({"tools": {"nuclei": ["boom"]}}))

        sent = {}
        result = run_monitor(
            ws,
            Config(),
            "example.com",
            webhook="https://hooks.slack.com/x",
            recon=_recon_noop,
            post=lambda u, p: sent.update(url=u, payload=p) or True,
        )
        assert result.first_run is False
        assert result.new_findings == ["boom"]
        assert result.notified is True
        assert "boom" in sent["payload"]["text"]
        # the fresh state was persisted as the new baseline
        assert "boom" in latest(ws).get("findings")

    def test_no_new_finding_does_not_notify_by_default(self, tmp_path):
        ws = _ws(tmp_path, subs=["a.example.com"])
        save(ws, capture(ws))
        # only a new subdomain — not a finding
        ws.append_unique("recon/subdomains.txt", ["b.example.com"])

        posts = []
        result = run_monitor(
            ws,
            Config(),
            "example.com",
            webhook="https://hooks.slack.com/x",
            recon=_recon_noop,
            post=lambda u, p: posts.append(1) or True,
        )
        assert result.has_changes is True  # subdomain delta exists
        assert result.new_findings == []
        assert result.notified is False
        assert posts == []

    def test_notify_on_changes_fires_for_any_delta(self, tmp_path):
        ws = _ws(tmp_path, subs=["a.example.com"])
        save(ws, capture(ws))
        ws.append_unique("recon/subdomains.txt", ["b.example.com"])

        posts = []
        result = run_monitor(
            ws,
            Config(),
            "example.com",
            webhook="https://hooks.slack.com/x",
            notify_on=NOTIFY_CHANGES,
            recon=_recon_noop,
            post=lambda u, p: posts.append(1) or True,
        )
        assert result.notified is True
        assert len(posts) == 1

    def test_no_webhook_means_no_send(self, tmp_path):
        ws = _ws(tmp_path, subs=["a.example.com"])
        save(ws, capture(ws))
        ws.path("scans/findings.json").write_text(json.dumps({"tools": {"nuclei": ["boom"]}}))

        result = run_monitor(ws, Config(), "example.com", recon=_recon_noop)
        assert result.new_findings == ["boom"]
        assert result.notified is False


class TestCli:
    def _home(self, tmp_path, monkeypatch):
        monkeypatch.delenv("HUNTKIT_HOME", raising=False)
        monkeypatch.setenv("HUNTKIT_GENERAL_WORKSPACE_PATH", str(tmp_path))
        monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "cfg"))
        monkeypatch.chdir(tmp_path)

    def test_rejects_bad_domain(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner

        from huntkit.app import app

        self._home(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["monitor", "not_a_domain"])
        assert result.exit_code == 2

    def test_rejects_bad_notify_on(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner

        from huntkit.app import app

        self._home(tmp_path, monkeypatch)
        CliRunner().invoke(app, ["init", "acme", "-s", "*.example.com"])
        result = CliRunner().invoke(
            app, ["monitor", "example.com", "-p", "acme", "--notify-on", "bogus"]
        )
        assert result.exit_code == 2

    def test_first_run_prints_baseline(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner

        import huntkit.app.main as main
        from huntkit.app import app
        from huntkit.history import Snapshot
        from huntkit.monitor import MonitorResult

        self._home(tmp_path, monkeypatch)
        CliRunner().invoke(app, ["init", "acme", "-s", "*.example.com"])

        snap = Snapshot(id="20260101-000000", generated="2026-01-01T00:00:00Z")
        fake = MonitorResult(
            program="acme",
            summary=None,
            report=None,
            snapshot=snap,
            baseline_id=None,
            notified=False,
            first_run=True,
        )
        monkeypatch.setattr(main, "run_monitor", lambda *a, **k: fake)
        result = CliRunner().invoke(app, ["monitor", "example.com", "-p", "acme"])
        assert result.exit_code == 0
        assert "baseline" in result.stdout

    def test_delta_run_reports_notified(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner

        import huntkit.app.main as main
        from huntkit.app import app
        from huntkit.history import CategoryDiff, DiffReport, Snapshot
        from huntkit.monitor import MonitorResult

        self._home(tmp_path, monkeypatch)
        CliRunner().invoke(app, ["init", "acme", "-s", "*.example.com"])

        report = DiffReport(
            program="acme",
            base_id="20260101-000000",
            base_time="t",
            new_id="20260102-000000",
            new_time="t",
            categories=[CategoryDiff(name="findings", added=["boom"], removed=[])],
        )
        fake = MonitorResult(
            program="acme",
            summary=None,
            report=report,
            snapshot=Snapshot(id="20260102-000000", generated="t"),
            baseline_id="20260101-000000",
            notified=True,
            first_run=False,
        )
        monkeypatch.setattr(main, "run_monitor", lambda *a, **k: fake)
        result = CliRunner().invoke(
            app, ["monitor", "example.com", "-p", "acme", "-u", "https://hooks.slack.com/x"]
        )
        assert result.exit_code == 0
        assert "boom" in result.stdout
        assert "notified" in result.stdout


class TestEvents:
    def test_emits_lifecycle_events(self, tmp_path):
        ws = _ws(tmp_path, subs=["a.example.com"])
        save(ws, capture(ws))
        ws.path("scans/findings.json").write_text(json.dumps({"tools": {"nuclei": ["boom"]}}))

        events = []
        run_monitor(
            ws,
            Config(),
            "example.com",
            webhook="https://hooks.slack.com/x",
            recon=_recon_noop,
            post=lambda u, p: True,
            on_event=events.append,
        )
        kinds = [e["event"] for e in events]
        assert kinds[0] == "monitor_start"
        assert "recon_begin" in kinds
        assert "notify" in kinds
        assert kinds[-1] == "monitor_done"
