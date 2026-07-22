import json
import sys

import pytest
from typer.testing import CliRunner

from huntkit.app import app
from huntkit.core.workspace import Workspace
from huntkit.knowledge import get_playbook
from huntkit.report import build, generate, normalise_format, render, write
from huntkit.report.render import _playbook_html

runner = CliRunner()

_PLAYBOOK_IDS = {"idor", "bac", "xss", "ssrf", "sqli", "ssti", "subtakeover", "authn", "cors"}


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
    ws.set_scope(["*.example.com"], [])
    return ws


# ---------------------------------------------------------------------------
# formats
# ---------------------------------------------------------------------------
class TestFormats:
    def test_normalise(self):
        assert normalise_format("MD") == "md"
        assert normalise_format("markdown") == "md"
        assert normalise_format(" HTM ") == "html"
        assert normalise_format("json") == "json"
        assert normalise_format("pdf") == "pdf"
        assert normalise_format("xml") is None


# ---------------------------------------------------------------------------
# build (composition)
# ---------------------------------------------------------------------------
class TestBuild:
    def test_build_composes_everything(self, tmp_path):
        rep = build(_seed(tmp_path))
        assert rep.program == "acme"
        assert rep.scope_in == ["*.example.com"]
        assert rep.recon["ports"] == 2 and rep.recon["urls"] == 2
        assert rep.has_findings and rep.has_data
        ids = [p.id for p in rep.playbooks]
        assert ids and set(ids) <= _PLAYBOOK_IDS
        assert len(ids) == len(set(ids))                 # de-duped

    def test_empty_workspace_has_no_data(self, tmp_path):
        rep = build(Workspace.open("empty", base=tmp_path))
        assert not rep.has_findings and not rep.has_data


# ---------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------
class TestMarkdown:
    def test_sections_and_nested_playbooks(self, tmp_path):
        md = render.to_markdown(build(_seed(tmp_path)))
        assert md.startswith("# HuntKit Report — acme")
        for head in ["## Summary", "## Prioritised hosts", "## Attack paths",
                     "## Notable exposures", "## Recon surface", "## Playbooks"]:
            assert head in md, head
        assert "*.example.com" in md
        assert "### " in md                              # playbook nested at h3
        assert md.endswith("\n")

    def test_notable_surfaces_redis(self, tmp_path):
        md = render.to_markdown(build(_seed(tmp_path)))
        assert "admin.example.com" in md and "Redis" in md


# ---------------------------------------------------------------------------
# html
# ---------------------------------------------------------------------------
class TestHtml:
    def test_selfcontained_and_styled(self, tmp_path):
        htm = render.to_html(build(_seed(tmp_path)))
        assert htm.startswith("<!doctype html>")
        assert "<style>" in htm                          # css inlined
        assert "<link" not in htm.lower() and "src=" not in htm  # no external assets
        assert "sev-critical" in htm and "<table" in htm and "<pre>" in htm

    def test_playbook_html_escapes_payloads(self):
        # the xss playbook carries <script> — must be escaped, never raw
        h = _playbook_html(get_playbook("xss"))
        assert "&lt;script&gt;" in h
        assert "<script>" not in h


# ---------------------------------------------------------------------------
# json
# ---------------------------------------------------------------------------
class TestJson:
    def test_shape(self, tmp_path):
        d = json.loads(render.to_json(build(_seed(tmp_path))))
        assert set(d) == {"program", "generated", "scope", "recon", "intel", "playbooks"}
        assert d["scope"]["in"] == ["*.example.com"]
        assert d["intel"]["hosts"] and d["recon"]["ports"] == 2
        assert d["playbooks"] and "id" in d["playbooks"][0]


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------
class TestWrite:
    @pytest.mark.parametrize("fmt,ext", [("md", "md"), ("html", "html"), ("json", "json")])
    def test_write_lands_in_reports(self, tmp_path, fmt, ext):
        ws = _seed(tmp_path)
        w = write(ws, build(ws), fmt)
        assert w.path.exists() and w.path.suffix == "." + ext and w.note == ""
        assert w.path.parent == ws.root / "reports"

    def test_out_override(self, tmp_path):
        ws = _seed(tmp_path)
        dest = tmp_path / "custom" / "r.md"
        w = write(ws, build(ws), "md", out=dest)
        assert w.path == dest and dest.exists()

    def test_pdf_without_backend_degrades(self, tmp_path, monkeypatch):
        # None in sys.modules makes `import weasyprint` raise -> HTML fallback
        monkeypatch.setitem(sys.modules, "weasyprint", None)
        ws = _seed(tmp_path)
        w = write(ws, build(ws), "pdf")
        assert w.path.suffix == ".html" and w.path.exists()
        assert "PDF backend" in w.note

    def test_generate_one_call(self, tmp_path):
        w = generate(_seed(tmp_path), "json")
        assert w.path.exists() and w.path.suffix == ".json"


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
    def test_writes_markdown(self, home):
        runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
        _seed(home)
        result = runner.invoke(app, ["report", "-p", "acme"])
        assert result.exit_code == 0
        assert "report —" in result.stdout and "report →" in result.stdout
        assert list((home / "acme" / "reports").glob("*.md"))

    def test_html_format(self, home):
        runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
        _seed(home)
        result = runner.invoke(app, ["report", "-p", "acme", "-f", "html"])
        assert result.exit_code == 0
        assert list((home / "acme" / "reports").glob("*.html"))

    def test_unknown_format_exits_2(self, home):
        runner.invoke(app, ["init", "acme", "-s", "example.com"])
        result = runner.invoke(app, ["report", "-p", "acme", "-f", "xml"])
        assert result.exit_code == 2

    def test_no_data_warns(self, home):
        runner.invoke(app, ["init", "empty", "-s", "example.com"])
        result = runner.invoke(app, ["report", "-p", "empty"])
        assert result.exit_code == 0
        assert "nothing to report" in result.stdout

    def test_requires_program_when_ambiguous(self, home):
        result = runner.invoke(app, ["report"])
        assert result.exit_code == 2
