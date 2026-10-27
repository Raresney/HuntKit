import json

from typer.testing import CliRunner

from huntkit.app import app
from huntkit.fingerprint import (
    FINGERPRINT_RULES,
    KINDS,
    fingerprint_headers,
    has_waf,
    parse_headers,
)
from huntkit.utils.severity import Severity

runner = CliRunner()

_HEADERS = (
    "HTTP/2 403\n"
    "server: cloudflare\n"
    "cf-ray: 7a1b2c3d-FRA\n"
    "x-powered-by: Express\n"
    "set-cookie: incap_ses_42=abc; path=/\n"
    "via: 1.1 vegur\n"
)


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------
class TestParse:
    def test_lowercases_and_skips_status(self):
        h = parse_headers("HTTP/1.1 200 OK\nServer: nginx\nX-Foo: Bar\nnotaheader\n")
        assert h == {"server": "nginx", "x-foo": "Bar"}

    def test_joins_repeated_headers(self):
        h = parse_headers("set-cookie: a=1\nset-cookie: b=2\n")
        assert h["set-cookie"] == "a=1; b=2"


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------
class TestRules:
    def test_catalog_well_formed(self):
        ids = [r.id for r in FINGERPRINT_RULES]
        assert len(ids) == len(set(ids))
        for r in FINGERPRINT_RULES:
            assert r.kind in KINDS
            assert isinstance(r.severity, Severity)
            assert r.headers  # at least one signal

    def test_waf_flagged_others_info(self):
        for r in FINGERPRINT_RULES:
            if r.kind == "waf":
                assert r.severity is Severity.MEDIUM
            else:
                assert r.severity is Severity.INFO


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------
class TestEngine:
    def test_mixed_stack_classified(self):
        ids = {m.id for m in fingerprint_headers(_HEADERS)}
        assert {"cloudflare", "express", "heroku", "imperva"} <= ids

    def test_waf_sorts_first(self):
        matches = fingerprint_headers(_HEADERS)
        assert matches[0].kind == "waf" and matches[0].id == "imperva"
        assert has_waf(matches)

    def test_cookie_fingerprints(self):
        ids = {m.id for m in fingerprint_headers("set-cookie: BIGipServerpool=1.2.3; path=/")}
        assert "f5-bigip" in ids

    def test_dict_input(self):
        ids = {m.id for m in fingerprint_headers({"Server": "nginx", "X-Powered-By": "PHP/8.1"})}
        assert ids == {"nginx", "php"}

    def test_no_match_is_empty(self):
        assert fingerprint_headers("x-foo: bar") == []

    def test_evidence_and_to_dict(self):
        [cf] = [m for m in fingerprint_headers("cf-ray: abc\n") if m.id == "cloudflare"]
        assert cf.evidence.startswith("cf-ray:")
        d = cf.to_dict()
        assert set(d) == {"id", "name", "kind", "severity", "evidence"}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class TestCli:
    def test_stdin_warns_on_waf(self):
        result = runner.invoke(app, ["fingerprint", "-"], input=_HEADERS)
        assert result.exit_code == 0
        assert "Cloudflare" in result.stdout and "Imperva" in result.stdout
        assert "WAF present" in result.stdout

    def test_file_and_json_out(self, tmp_path):
        (tmp_path / "h.txt").write_text(_HEADERS, encoding="utf-8")
        out = tmp_path / "fp.json"
        result = runner.invoke(app, ["fingerprint", str(tmp_path / "h.txt"), "--out", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data[0]["kind"] == "waf" and any(m["id"] == "cloudflare" for m in data)

    def test_no_match_exits_0(self):
        result = runner.invoke(app, ["fingerprint", "-"], input="x-foo: bar\n")
        assert result.exit_code == 0 and "no CDN/WAF" in result.stdout

    def test_missing_file_exits_2(self, tmp_path):
        result = runner.invoke(app, ["fingerprint", str(tmp_path / "nope.txt")])
        assert result.exit_code == 2
