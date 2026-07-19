import pytest
from typer.testing import CliRunner

from huntkit.app import app
from huntkit.intel.engine import PLAYBOOK_NAMES
from huntkit.knowledge import (
    PLAYBOOKS,
    Reference,
    all_playbooks,
    get_playbook,
    titles,
)
from huntkit.utils.severity import Severity

runner = CliRunner()


# ---------------------------------------------------------------------------
# shared severity vocabulary
# ---------------------------------------------------------------------------
class TestSeverityShared:
    def test_intel_and_knowledge_share_one_enum(self):
        # Severity moved to utils; intel must re-export the *same* object so
        # phase-5 imports keep working and comparisons stay valid.
        from huntkit.intel import Severity as IntelSeverity

        assert IntelSeverity is Severity

    def test_from_name_roundtrips_label(self):
        for s in Severity:
            assert Severity.from_name(s.label) is s
        assert Severity.from_name("info") is Severity.INFO
        assert Severity.from_name(" HIGH ") is Severity.HIGH
        with pytest.raises(ValueError):
            Severity.from_name("bogus")


# ---------------------------------------------------------------------------
# catalog integrity
# ---------------------------------------------------------------------------
class TestCatalog:
    def test_cross_link_contract(self):
        # every id the intel layer points at must be documented here, and
        # vice-versa — that's what makes attack-paths -> `playbook <id>` work.
        assert set(PLAYBOOK_NAMES) == set(PLAYBOOKS)

    def test_names_sourced_from_knowledge(self):
        assert PLAYBOOK_NAMES == titles()

    def test_playbooks_are_well_formed(self):
        for pid, pb in PLAYBOOKS.items():
            assert pb.id == pid                     # keyed by its own id
            assert isinstance(pb.severity, Severity)
            assert pb.title.strip()
            assert pb.summary.strip() and pb.when.strip()
            assert pb.detection                     # at least one detection step

    def test_references_look_like_links(self):
        for pb in all_playbooks():
            for ref in pb.references:
                assert isinstance(ref, Reference)
                assert ref.name.strip()
                assert ref.url.startswith("https://")

    def test_get_playbook_case_insensitive(self):
        assert get_playbook("SSRF") is PLAYBOOKS["ssrf"]
        assert get_playbook("  ssrf ") is PLAYBOOKS["ssrf"]
        assert get_playbook("does-not-exist") is None


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------
class TestRendering:
    def test_to_dict_shape(self):
        d = PLAYBOOKS["idor"].to_dict()
        assert set(d) == {
            "id", "title", "severity", "summary", "when",
            "detection", "payloads", "bypasses", "tools", "references",
        }
        assert d["severity"] == "high"
        assert d["references"][0]["url"].startswith("https://")

    def test_to_markdown_has_sections(self):
        md = PLAYBOOKS["ssrf"].to_markdown()
        assert md.startswith("# Server-Side Request Forgery")
        assert "## Detection" in md
        assert "## Payloads" in md
        assert "## References" in md
        assert md.endswith("\n")

    def test_markdown_omits_empty_sections(self):
        # subtakeover carries no bypasses -> no Bypasses heading emitted
        md = PLAYBOOKS["subtakeover"].to_markdown()
        assert "## Detection" in md
        assert "## Bypasses" not in md


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
@pytest.fixture
def home(tmp_path, monkeypatch):
    # hermetic: never read the real ~/.huntkit while building the app context
    monkeypatch.delenv("HUNTKIT_HOME", raising=False)
    monkeypatch.setenv("HUNTKIT_GENERAL_WORKSPACE_PATH", str(tmp_path))
    monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestCli:
    def test_list_all(self, home):
        result = runner.invoke(app, ["playbook"])
        assert result.exit_code == 0
        assert "knowledge base" in result.stdout
        for pid in PLAYBOOKS:
            assert pid in result.stdout

    def test_render_one(self, home):
        result = runner.invoke(app, ["playbook", "ssrf"])
        assert result.exit_code == 0
        assert "Payloads" in result.stdout
        assert "169.254.169.254" in result.stdout   # a real payload rendered

    def test_render_case_insensitive(self, home):
        result = runner.invoke(app, ["playbook", "SSRF"])
        assert result.exit_code == 0
        assert "Detection" in result.stdout

    def test_markdown_flag(self, home):
        result = runner.invoke(app, ["playbook", "sqli", "--md"])
        assert result.exit_code == 0
        assert result.stdout.startswith("# SQL / NoSQL Injection")
        assert "## Payloads" in result.stdout

    def test_bracket_payloads_survive_markup(self, home):
        # sqli payloads carry [$ne] etc. — must not blow up Rich markup parsing
        result = runner.invoke(app, ["playbook", "sqli"])
        assert result.exit_code == 0
        assert "$ne" in result.stdout

    def test_unknown_exits_2(self, home):
        result = runner.invoke(app, ["playbook", "nope"])
        assert result.exit_code == 2
        assert "pick one" in result.stdout          # id hint goes to stdout
