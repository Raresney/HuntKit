import json

from typer.testing import CliRunner

from huntkit.app import app
from huntkit.secrets import (
    SECRET_PATTERNS,
    endpoints_from_paths,
    extract_endpoints,
    redact,
    scan_paths,
    scan_text,
    shannon_entropy,
)
from huntkit.utils.severity import Severity

runner = CliRunner()

_AKIA = "AKIAIOSFODNN7EXAMPLE"
_GHP = "ghp_" + "a" * 36
_AIZA = "AIza" + "B" * 35
_HIGH_ENTROPY = "aT9xQ2w8ZkLm5RpV"  # looks like a random key value


def _sample() -> str:
    return (
        f'const awsKey = "{_AKIA}";\n'
        f"headers.set('Authorization', 'token {_GHP}');\n"
        f'const g = "{_AIZA}";\n'
        f'var cfg = {{api_key: "{_HIGH_ENTROPY}"}};\n'
        'password = "password";\n'  # low entropy -> filtered
        "-----BEGIN RSA PRIVATE KEY-----\n"
        'const api = "/api/v2/users?id=1"; fetch("https://x.com/internal/admin");\n'
        'img = "/assets/logo.png";\n'
    )


# ---------------------------------------------------------------------------
# patterns
# ---------------------------------------------------------------------------
class TestPatterns:
    def test_entropy_orders_random_above_words(self):
        assert shannon_entropy("aaaaaaaa") < shannon_entropy("aT9xQ2w8ZkLm")
        assert shannon_entropy("") == 0.0

    def test_catalog_is_well_formed(self):
        ids = [p.id for p in SECRET_PATTERNS]
        assert len(ids) == len(set(ids))  # unique ids
        for p in SECRET_PATTERNS:
            assert isinstance(p.severity, Severity)
            assert p.regex.groups >= p.group  # declared group exists

    def test_known_keys_match(self):
        ids = {h.id for h in scan_text(_sample())}
        assert {
            "aws-access-key",
            "github-token",
            "gcp-api-key",
            "generic-secret",
            "private-key",
        } <= ids

    def test_low_entropy_generic_is_filtered(self):
        # the literal word "password" must not be flagged as a generic secret
        hits = scan_text('password = "password";')
        assert hits == []


# ---------------------------------------------------------------------------
# scanner + redaction
# ---------------------------------------------------------------------------
class TestScanner:
    def test_redact_masks_the_middle(self):
        r = redact(_AKIA)
        assert _AKIA not in r and r.startswith("AKIA") and "chars)" in r
        assert redact("short") == "*****"

    def test_no_raw_secret_ever_in_output(self):
        hits = scan_text(_sample(), source="app.js")
        blob = " ".join(h.match for h in hits) + json.dumps([h.to_dict() for h in hits])
        for raw in (_AKIA, _GHP, _AIZA, _HIGH_ENTROPY):
            assert raw not in blob

    def test_line_numbers_and_source(self):
        [hit] = [h for h in scan_text(_sample(), source="x.js") if h.id == "aws-access-key"]
        assert hit.line == 1 and hit.source == "x.js"

    def test_dedupes_repeat_on_same_line(self):
        line = f'a="{_AKIA}" b="{_AKIA}"'
        assert len(scan_text(line)) == 1  # same value, same line -> one hit

    def test_scan_paths_walks_and_skips_binary(self, tmp_path):
        (tmp_path / "a.js").write_text(f'k="{_AKIA}"', encoding="utf-8")
        (tmp_path / "logo.png").write_bytes(_AKIA.encode())  # binary ext -> skipped
        hits = scan_paths([tmp_path])
        assert len(hits) == 1 and hits[0].id == "aws-access-key"


class TestEndpoints:
    def test_extract_filters_assets(self):
        eps = extract_endpoints(_sample())
        assert "/api/v2/users?id=1" in eps
        assert "https://x.com/internal/admin" in eps
        assert not any(e.endswith(".png") for e in eps)

    def test_endpoints_from_paths_dedupes(self, tmp_path):
        (tmp_path / "a.js").write_text('fetch("/api/x")', encoding="utf-8")
        (tmp_path / "b.js").write_text('fetch("/api/x"); fetch("/api/y")', encoding="utf-8")
        assert endpoints_from_paths([tmp_path]) == ["/api/x", "/api/y"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class TestCli:
    def test_scan_prints_redacted(self, tmp_path):
        (tmp_path / "app.js").write_text(f'var k="{_AKIA}"; fetch("/api/me");', encoding="utf-8")
        result = runner.invoke(app, ["secrets", str(tmp_path)])
        assert result.exit_code == 0
        assert "critical" in result.stdout and "AWS access key" in result.stdout
        assert _AKIA not in result.stdout  # redacted in the table

    def test_endpoints_and_json_out(self, tmp_path):
        (tmp_path / "app.js").write_text(
            f'var k="{_AKIA}"; fetch("/api/me"); i="/x.png";', encoding="utf-8"
        )
        out = tmp_path / "sec.json"
        result = runner.invoke(app, ["secrets", str(tmp_path), "--endpoints", "--out", str(out)])
        assert result.exit_code == 0 and "/api/me" in result.stdout
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["secrets"] and data["endpoints"] == ["/api/me"]
        assert _AKIA not in out.read_text(encoding="utf-8")  # redacted in JSON too

    def test_missing_path_exits_2(self, tmp_path):
        result = runner.invoke(app, ["secrets", str(tmp_path / "nope")])
        assert result.exit_code == 2

    def test_clean_dir_reports_nothing(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello world", encoding="utf-8")
        result = runner.invoke(app, ["secrets", str(tmp_path)])
        assert result.exit_code == 0 and "no secrets matched" in result.stdout
