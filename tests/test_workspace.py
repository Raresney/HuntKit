from huntkit.core.config import Config
from huntkit.core.workspace import Workspace, default_base, list_workspaces


def _ws(tmp_path, name="acme"):
    return Workspace.open(name, base=tmp_path)


def test_open_creates_layout(tmp_path):
    ws = _ws(tmp_path)
    assert ws.root.is_dir()
    for sub in ("scope", "recon", "urls", "scans", "reports"):
        assert (ws.root / sub).is_dir()


def test_program_name_is_sanitised(tmp_path):
    ws = Workspace.open("../../evil name", base=tmp_path)
    # stays inside base, no traversal
    assert str(ws.root.resolve()).startswith(str(tmp_path.resolve()))
    assert "evil" in ws.root.name


def test_scope_roundtrip_and_matching(tmp_path):
    ws = _ws(tmp_path)
    ws.set_scope(["*.example.com", "10.0.0.0/24"], ["admin.example.com"])
    assert ws.scope_in == ["*.example.com", "10.0.0.0/24"]
    assert ws.has_scope()
    # wildcard covers apex + subs
    assert ws.in_scope("example.com")
    assert ws.in_scope("api.example.com")
    # explicit out-of-scope wins over the wildcard
    assert not ws.in_scope("admin.example.com")
    # unrelated host is excluded once an in-scope list exists
    assert not ws.in_scope("other.org")


def test_no_scope_means_everything_in(tmp_path):
    ws = _ws(tmp_path)
    assert not ws.has_scope()
    assert ws.in_scope("anything.com")


def test_filter_scope(tmp_path):
    ws = _ws(tmp_path)
    ws.set_scope(["*.example.com"], [])
    hosts = ["a.example.com", "evil.org", "b.example.com"]
    assert ws.filter_scope(hosts) == ["a.example.com", "b.example.com"]


def test_result_files_dedupe_and_count(tmp_path):
    ws = _ws(tmp_path)
    assert ws.append_unique("recon/subdomains.txt", ["b.com", "a.com", "a.com"]) == 2
    assert ws.read_lines("recon/subdomains.txt") == ["a.com", "b.com"]
    assert ws.count("recon/subdomains.txt") == 2
    assert ws.append_unique("recon/subdomains.txt", ["a.com", "c.com"]) == 1


def test_state_is_wired(tmp_path):
    ws = _ws(tmp_path)
    ws.state.done("subs", total=3)
    ws.state.set_count("subdomains", 3)
    # reopen from disk
    ws2 = _ws(tmp_path)
    assert ws2.state.is_done("subs")
    assert ws2.state.counts["subdomains"] == 3


def test_default_base_prefers_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTKIT_HOME", str(tmp_path / "envhome"))
    assert default_base() == tmp_path / "envhome"
    monkeypatch.delenv("HUNTKIT_HOME")
    cfg = Config.from_dict({"general": {"workspace_path": str(tmp_path / "cfghome")}})
    assert default_base(cfg) == tmp_path / "cfghome"


def test_list_workspaces(tmp_path):
    assert list_workspaces(base=tmp_path) == []
    a = Workspace.open("alpha", base=tmp_path)
    a.state.save()  # creates state.json → counts as a workspace
    Workspace.open("beta", base=tmp_path).state.save()
    assert list_workspaces(base=tmp_path) == ["alpha", "beta"]
