import time

from huntkit.core.cache import Cache, make_key
from huntkit.core.state import StageStatus, StateStore


class TestCache:
    def test_set_get_roundtrip(self, tmp_path):
        c = Cache(tmp_path)
        c.set("k", "value")
        assert c.get("k") == "value"

    def test_miss_returns_none(self, tmp_path):
        assert Cache(tmp_path).get("absent") is None

    def test_ttl_expiry(self, tmp_path):
        c = Cache(tmp_path, ttl_seconds=1)
        c.set("k", "v")
        assert c.get("k") == "v"
        # forge an old timestamp instead of sleeping
        import json

        p = tmp_path / "k.json"
        rec = json.loads(p.read_text())
        rec["ts"] = time.time() - 10
        p.write_text(json.dumps(rec))
        assert c.get("k") is None

    def test_disabled(self, tmp_path):
        c = Cache(tmp_path, enabled=False)
        c.set("k", "v")
        assert c.get("k") is None

    def test_clear(self, tmp_path):
        c = Cache(tmp_path)
        c.set("a", "1")
        c.set("b", "2")
        assert c.clear() == 2
        assert c.get("a") is None

    def test_make_key_stable_and_distinct(self):
        assert make_key("subfinder", "-d", "x.com") == make_key("subfinder", "-d", "x.com")
        assert make_key("a") != make_key("b")


class TestStateStore:
    def test_stage_lifecycle(self, tmp_path):
        s = StateStore(tmp_path / "state.json")
        assert s.status("recon") == StageStatus.PENDING
        s.start("recon")
        assert s.status("recon") == StageStatus.RUNNING
        s.done("recon", total=42)
        assert s.is_done("recon")
        assert s.stages["recon"].meta["total"] == 42
        assert s.stages["recon"].duration is not None

    def test_failure_recorded(self, tmp_path):
        s = StateStore(tmp_path / "state.json")
        s.start("scan")
        s.fail("scan", "boom")
        assert s.status("scan") == StageStatus.FAILED
        assert s.failed() == ["scan"]

    def test_pending_is_resume_set(self, tmp_path):
        s = StateStore(tmp_path / "state.json")
        s.done("subs")
        pending = s.pending(["subs", "live", "ports"])
        assert pending == ["live", "ports"]

    def test_persistence_reload(self, tmp_path):
        path = tmp_path / "state.json"
        s = StateStore(path)
        s.done("subs", total=3)
        s.set_count("subdomains", 3)
        # reopen from disk
        s2 = StateStore(path)
        assert s2.is_done("subs")
        assert s2.counts["subdomains"] == 3

    def test_reset(self, tmp_path):
        s = StateStore(tmp_path / "state.json")
        s.done("subs")
        s.reset()
        assert not s.is_done("subs")
