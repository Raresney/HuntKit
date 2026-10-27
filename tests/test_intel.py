import json

import pytest
from typer.testing import CliRunner

from huntkit.app import app
from huntkit.core.workspace import Workspace
from huntkit.intel import (
    Priority,
    Severity,
    Signal,
    analyze,
    save_report,
    scan_signals,
    signals_from_findings,
    signals_from_labels,
    signals_from_params,
    signals_from_paths,
    signals_from_ports,
)
from huntkit.intel.engine import HostIntel, _priority

runner = CliRunner()


# ---------------------------------------------------------------------------
# enums
# ---------------------------------------------------------------------------
class TestEnums:
    def test_severity_order_and_labels(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
        assert Severity.INFO.label == "informational"   # theme key
        assert Severity.HIGH.label == "high"
        assert Severity.CRITICAL.style == "critical"

    def test_priority_order_and_labels(self):
        assert Priority.CRITICAL > Priority.LOW
        assert Priority.HIGH.label == "High"
        assert Priority.MEDIUM.style == "medium"


# ---------------------------------------------------------------------------
# matchers
# ---------------------------------------------------------------------------
class TestPortSignals:
    def test_known_ports_map_to_severity(self):
        sigs = {s.id: s for s in signals_from_ports(["1.2.3.4:6379", "1.2.3.4:22"])}
        assert sigs["redis-open"].severity is Severity.CRITICAL
        assert sigs["ssh-open"].severity is Severity.INFO
        assert sigs["redis-open"].host == "1.2.3.4"

    def test_unknown_and_malformed_ignored(self):
        assert signals_from_ports(["1.2.3.4:99999", "1.2.3.4", "garbage", ""]) == []

    def test_repeated_port_collapses_with_count(self):
        sigs = signals_from_ports(["a.com:8080", "a.com:8080"])
        assert len(sigs) == 1 and sigs[0].count == 2


class TestPathSignals:
    def test_interesting_paths(self):
        urls = [
            "https://x.com/.git/config",
            "https://x.com/.env",
            "http://y.com/actuator/env",
            "https://z.com/admin/login",
        ]
        by = {(s.host, s.id) for s in signals_from_paths(urls)}
        assert ("x.com", "git-exposed") in by
        assert ("x.com", "env-exposed") in by
        assert ("y.com", "spring-actuator") in by
        assert ("z.com", "admin-panel") in by

    def test_env_is_critical(self):
        [s] = [s for s in signals_from_paths(["https://x.com/.env"]) if s.id == "env-exposed"]
        assert s.severity is Severity.CRITICAL

    def test_no_host_or_no_path_skipped(self):
        assert signals_from_paths(["not a url", "https://x.com"]) == []

    def test_same_rule_same_host_dedupes(self):
        sigs = signals_from_paths(["https://x.com/admin", "https://x.com/admin/users"])
        admin = [s for s in sigs if s.id == "admin-panel"]
        assert len(admin) == 1 and admin[0].count == 2


class TestParamSignals:
    def test_param_class_priority_first_wins(self):
        # a url carrying one of each: each name resolves to its class
        cases = {
            "cmd": "cmd-param",
            "url": "ssrf-param",
            "token": "secret-param",
            "file": "lfi-param",
            "sort": "sqli-param",
            "q": "reflect-param",
            "id": "idor-param",
        }
        for name, want in cases.items():
            sigs = signals_from_params([f"https://x.com/p?{name}=1"])
            assert [s.id for s in sigs] == [want], name

    def test_unknown_param_ignored(self):
        assert signals_from_params(["https://x.com/p?zzz=1"]) == []

    def test_ssrf_param_carries_playbook(self):
        [s] = signals_from_params(["https://x.com/p?redirect=1"])
        assert s.playbooks == ("ssrf",)


class TestLabelSignals:
    def test_exact_and_prefix_labels(self):
        sigs = {(s.host, s.id) for s in signals_from_labels(["dev01.example.com"])}
        assert ("dev01.example.com", "nonprod-host") in sigs   # dev -> prefix match

    def test_multiple_labels_one_host(self):
        sigs = {s.id for s in signals_from_labels(["api.dev.example.com"])}
        assert {"api-host", "nonprod-host"} <= sigs

    def test_exact_beats_prefix_severity(self):
        # 'gitlab' (exact, High) must win over the 'git' prefix rule (Medium)
        [s] = [s for s in signals_from_labels(["gitlab.example.com"]) if s.id == "git-host"]
        assert s.severity is Severity.HIGH

    def test_plain_word_no_false_match(self):
        assert signals_from_labels(["www.example.com"]) == []


def test_scan_signals_merges_all_matchers():
    sigs = scan_signals(
        ports=["a.com:6379"],
        urls=["https://a.com/admin?id=1"],
        hosts=["dev.a.com"],
    )
    cats = {s.category for s in sigs}
    assert cats == {"port", "path", "param", "subdomain"}


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------
def _sig(sev, pb=()):
    return Signal("x", "x", sev, "path", "h", "e", pb)


class TestScoring:
    def test_priority_from_top_severity(self):
        assert _priority([_sig(Severity.CRITICAL)]) is Priority.CRITICAL
        assert _priority([_sig(Severity.HIGH)]) is Priority.HIGH
        assert _priority([_sig(Severity.MEDIUM)]) is Priority.MEDIUM
        assert _priority([_sig(Severity.LOW)]) is Priority.LOW
        assert _priority([]) is Priority.LOW

    def test_aggregate_lifts_priority(self):
        # four LOWs (2*4 = 8) crosses the High aggregate threshold
        assert _priority([_sig(Severity.LOW)] * 4) is Priority.HIGH
        # two LOWs (4) reach Medium without any medium signal
        assert _priority([_sig(Severity.LOW)] * 2) is Priority.MEDIUM

    def test_hostintel_playbooks_ordered_by_severity(self):
        h = HostIntel("h", [
            _sig(Severity.LOW, ("idor",)),
            _sig(Severity.HIGH, ("ssrf",)),
            _sig(Severity.MEDIUM, ("bac", "ssrf")),
        ])
        # ssrf first (from the High signal), then bac; ssrf not repeated
        assert h.playbooks == ["ssrf", "bac", "idor"]
        assert h.score == int(Severity.LOW) + int(Severity.HIGH) + int(Severity.MEDIUM)


class TestFindingSignals:
    def test_nuclei_line_severity_and_host(self):
        line = "[spring-env-actuator] [http] [critical] https://api.example.com/actuator/env"
        sigs = signals_from_findings({"nuclei": [line]})
        assert len(sigs) == 1
        s = sigs[0]
        assert s.severity is Severity.CRITICAL
        assert s.host == "api.example.com"
        assert s.category == "finding"
        assert s.id == "nuclei-spring-env-actuator"

    def test_nuclei_defaults_to_medium_without_severity_token(self):
        sigs = signals_from_findings({"nuclei": ["[weird] https://a.example.com/x"]})
        assert sigs[0].severity is Severity.MEDIUM

    def test_dalfox_is_high_xss(self):
        sigs = signals_from_findings({"dalfox": ["[POC][G][GET] https://api.example.com/?q=<svg>"]})
        assert sigs[0].severity is Severity.HIGH
        assert sigs[0].playbooks == ("xss",)
        assert sigs[0].id == "dalfox-xss"

    def test_repeated_finding_on_host_collapses(self):
        line = "[cve-2024-0001] [http] [high] https://api.example.com/a"
        line2 = "[cve-2024-0001] [http] [high] https://api.example.com/b"
        sigs = signals_from_findings({"nuclei": [line, line2]})
        assert len(sigs) == 1 and sigs[0].count == 2

    def test_lines_without_a_url_are_ignored(self):
        assert signals_from_findings({"nuclei": ["", "no url here", "[info]"]}) == []


# ---------------------------------------------------------------------------
# engine over a workspace
# ---------------------------------------------------------------------------
def _seed(tmp_path) -> Workspace:
    ws = Workspace.open("acme", base=tmp_path)
    ws.append_unique("recon/subdomains.txt",
                     ["api.dev.example.com", "admin.example.com", "www.example.com"])
    ws.append_unique("recon/resolved.txt", ["api.dev.example.com", "admin.example.com"])
    ws.append_unique("recon/live.txt",
                     ["https://api.dev.example.com", "https://admin.example.com"])
    ws.append_unique("recon/ports.txt", ["admin.example.com:6379", "www.example.com:22"])
    ws.append_unique("urls/urls.txt", [
        "https://api.dev.example.com/admin?id=5&redirect=http://x",
        "https://api.dev.example.com/.git/config",
    ])
    return ws


class TestAnalyze:
    def test_ranking_and_summary(self, tmp_path):
        report = analyze(_seed(tmp_path))
        assert [h.host for h in report.hosts][0] == "admin.example.com"  # redis -> Critical, ranked first
        assert report.hosts[0].priority is Priority.CRITICAL
        # summary is fully populated, highest first
        assert list(report.summary.keys()) == ["Critical", "High", "Medium", "Low"]
        assert report.summary["Critical"] == 1

    def test_host_pool_covers_all_sources(self, tmp_path):
        report = analyze(_seed(tmp_path))
        hosts = {h.host for h in report.hosts}
        # www came only from subdomains/ports; it still gets analysed
        assert "www.example.com" in hosts

    def test_attack_paths_sorted_by_severity(self, tmp_path):
        report = analyze(_seed(tmp_path))
        paths = report.attack_paths()
        sev = [int(p.severity) for p in paths]
        assert sev == sorted(sev, reverse=True)
        assert {p.playbook for p in paths} & {"ssrf", "idor", "authn", "bac"}

    def test_to_dict_shape(self, tmp_path):
        d = analyze(_seed(tmp_path)).to_dict()
        assert set(d) == {"program", "generated", "summary", "hosts", "attack_paths"}
        assert d["hosts"][0]["signals"]  # each host carries its signals
        assert "severity" in d["attack_paths"][0]

    def test_empty_workspace_no_signals(self, tmp_path):
        ws = Workspace.open("empty", base=tmp_path)
        report = analyze(ws)
        assert report.signals == []
        assert report.summary == {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    def test_save_report_writes_json_and_count(self, tmp_path):
        ws = _seed(tmp_path)
        report = analyze(ws)
        path = save_report(ws, report)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["program"] == "acme"
        assert ws.state.counts["intel_signals"] == len(report.signals)

    def test_scan_findings_fold_into_scoring(self, tmp_path):
        ws = _seed(tmp_path)
        # www only had ssh (INFO) -> Low; a critical scan finding must lift it
        ws.path("scans", "findings.json").write_text(json.dumps({
            "tools": {"nuclei": [
                "[cve-2024-9999] [http] [critical] https://www.example.com/rce",
            ]},
        }), encoding="utf-8")
        report = analyze(ws)
        www = next(h for h in report.hosts if h.host == "www.example.com")
        assert www.priority is Priority.CRITICAL
        assert any(s.category == "finding" for s in www.signals)

    def test_malformed_findings_json_is_ignored(self, tmp_path):
        ws = _seed(tmp_path)
        ws.path("scans", "findings.json").write_text("{ not json", encoding="utf-8")
        # analyze still succeeds, just without finding signals
        report = analyze(ws)
        assert all(s.category != "finding" for s in report.signals)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTKIT_HOME", raising=False)
    monkeypatch.setenv("HUNTKIT_GENERAL_WORKSPACE_PATH", str(tmp_path))
    monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestCli:
    def test_analyze_prints_and_writes(self, home):
        runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
        _seed(home)  # seed recon artifacts into the same base
        result = runner.invoke(app, ["analyze", "-p", "acme"])
        assert result.exit_code == 0
        assert "Prioritised hosts" in result.stdout
        assert "Critical" in result.stdout
        assert (home / "acme" / "scans" / "intel.json").exists()

    def test_analyze_no_data_warns(self, home):
        runner.invoke(app, ["init", "empty", "-s", "example.com"])
        result = runner.invoke(app, ["analyze", "-p", "empty"])
        assert result.exit_code == 0
        assert "no signals" in result.stdout

    def test_analyze_requires_program_when_ambiguous(self, home):
        # no workspaces at all -> cannot guess one
        result = runner.invoke(app, ["analyze"])
        assert result.exit_code == 2
