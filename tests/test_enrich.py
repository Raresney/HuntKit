import json

import pytest
from typer.testing import CliRunner

from huntkit.app import app
from huntkit.core.workspace import Workspace
from huntkit.enrich import (
    asn_for,
    enrich_hosts,
    enrich_origins,
    favicon_hash,
    favicon_url,
    hash_favicon,
    parse_cymru,
    run_enrich,
)
from huntkit.enrich.engine import default_fetch
from huntkit.enrich.mmh3 import hash_bytes

runner = CliRunner()


# --- mmh3 (ported) --------------------------------------------------------
class TestMmh3:
    def test_known_vectors(self):
        # locked against the reference `mmh3` C package (seed 0, signed)
        assert hash_bytes(b"") == 0
        assert hash_bytes(b"foo") == -156908512
        assert hash_bytes(b"hello") == 613153351

    def test_unsigned_flag(self):
        signed = hash_bytes(b"foo")
        unsigned = hash_bytes(b"foo", signed=False)
        assert unsigned == signed + 2**32
        assert 0 <= unsigned < 2**32


# --- favicon --------------------------------------------------------------
class TestFavicon:
    def test_favicon_url_normalises_to_origin(self):
        assert favicon_url("https://x.example.com/a/b?q=1") == "https://x.example.com/favicon.ico"
        assert favicon_url("x.example.com") == "http://x.example.com/favicon.ico"

    def test_hash_is_shodan_convention(self):
        # base64(encodebytes) then mmh3 — locked value cross-checked vs mmh3
        data = b"\x00\x01\x02\x03" * 40
        assert favicon_hash(data) == -1008687398

    def test_hash_favicon_success(self):
        data = b"icon-bytes"
        res = hash_favicon("https://x.example.com", fetch=lambda _u: data)
        assert res.ok
        assert res.url == "https://x.example.com/favicon.ico"
        assert res.hash == favicon_hash(data)
        assert res.shodan == f"http.favicon.hash:{res.hash}"

    def test_hash_favicon_empty(self):
        res = hash_favicon("https://x.example.com", fetch=lambda _u: b"")
        assert not res.ok and res.error == "empty response"

    def test_hash_favicon_too_large(self):
        res = hash_favicon("https://x.example.com", fetch=lambda _u: b"x" * (2 * 1024 * 1024))
        assert not res.ok and res.error == "too large"

    def test_hash_favicon_fetch_raises(self):
        def boom(_u):
            raise OSError("connection refused")

        res = hash_favicon("https://x.example.com", fetch=boom)
        assert not res.ok and "connection refused" in res.error


# --- asn ------------------------------------------------------------------
CYMRU_OK = (
    "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
    "13335   | 1.1.1.1          | 1.1.1.0/24          | US | arin     | 2010-07-14 | CLOUDFLARENET, US\n"
)


class TestAsn:
    def test_parse_cymru_data_row(self):
        row = parse_cymru(CYMRU_OK)
        assert row["asn"] == "13335"
        assert row["ip"] == "1.1.1.1"
        assert row["prefix"] == "1.1.1.0/24"
        assert row["cc"] == "US"
        assert row["as_name"] == "CLOUDFLARENET, US"

    def test_parse_cymru_header_only_is_empty(self):
        header = CYMRU_OK.splitlines()[0]
        assert parse_cymru(header) == {}

    def test_parse_cymru_garbage_is_empty(self):
        assert parse_cymru("no pipes here\njust text") == {}

    def test_asn_for_success(self):
        res = asn_for(
            "www.example.com",
            resolve=lambda _h: "1.1.1.1",
            lookup=lambda _ip: CYMRU_OK,
        )
        assert res.ok
        assert res.asn == "13335"
        assert res.prefix == "1.1.1.0/24"
        assert res.as_name == "CLOUDFLARENET, US"

    def test_asn_for_resolve_failure(self):
        def boom(_h):
            raise OSError("NXDOMAIN")

        res = asn_for("nope.example.com", resolve=boom, lookup=lambda _ip: CYMRU_OK)
        assert not res.ok and res.error.startswith("resolve:")

    def test_asn_for_lookup_failure(self):
        def boom(_ip):
            raise TimeoutError("whois timeout")

        res = asn_for("www.example.com", resolve=lambda _h: "1.1.1.1", lookup=boom)
        assert not res.ok and res.error.startswith("lookup:") and res.ip == "1.1.1.1"

    def test_asn_for_no_asn_in_reply(self):
        res = asn_for(
            "www.example.com",
            resolve=lambda _h: "1.1.1.1",
            lookup=lambda _ip: "NO DATA",
        )
        assert not res.ok and res.error == "no ASN in response"


# --- engine ---------------------------------------------------------------
def _ws(tmp_path, live=None, urls=None, resolved=None):
    ws = Workspace.open("t", base=tmp_path)
    ws.set_scope(["*.example.com"], [])
    if live:
        ws.append_unique("recon/live.txt", live)
    if urls:
        ws.append_unique("urls/urls.txt", urls)
    if resolved:
        ws.append_unique("recon/resolved.txt", resolved)
    return ws


class TestTargets:
    def test_origins_dedupe_per_origin_and_scope_filter(self, tmp_path):
        ws = _ws(
            tmp_path,
            live=["https://api.example.com/a", "https://api.example.com/b"],
            urls=["https://evil.com/x", "http://blog.example.com/y"],
        )
        origins = enrich_origins(ws)
        assert origins == ["http://blog.example.com", "https://api.example.com"]
        assert all("evil.com" not in o for o in origins)

    def test_hosts_union_scope_filtered(self, tmp_path):
        ws = _ws(
            tmp_path,
            live=["https://api.example.com"],
            resolved=["db.example.com", "evil.com"],
        )
        hosts = enrich_hosts(ws)
        assert hosts == ["api.example.com", "db.example.com"]


class TestRunEnrich:
    def test_end_to_end_with_stubs(self, tmp_path):
        ws = _ws(
            tmp_path,
            live=["https://api.example.com", "https://www.example.com"],
            resolved=["api.example.com"],
        )
        report = run_enrich(
            ws,
            fetch=lambda _u: b"shared-icon",
            resolve=lambda _h: "1.1.1.1",
            lookup=lambda _ip: CYMRU_OK,
        )
        assert report.favicon_hits == 2
        assert report.asn_hits >= 2
        # same icon → same hash across origins (the correlation signal)
        assert len({f.hash for f in report.favicons}) == 1
        assert report.unique_asns == ["13335"]

        data = json.loads(ws.path("scans/enrich.json").read_text())
        assert data["program"] == "t"
        assert len(data["favicons"]) == 2
        assert ws.state.is_done("enrich")

    def test_crashing_worker_is_isolated(self, tmp_path):
        ws = _ws(tmp_path, live=["https://api.example.com", "https://www.example.com"])

        calls = {"n": 0}

        def flaky(_u):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            return b"icon"

        report = run_enrich(ws, do_asn=False, fetch=flaky)
        # one crashed, one survived — the batch is not sunk
        assert report.favicon_hits == 1

    def test_selectors(self, tmp_path):
        ws = _ws(tmp_path, live=["https://api.example.com"])
        r1 = run_enrich(ws, do_asn=False, fetch=lambda _u: b"i")
        assert r1.asns == [] and r1.favicon_hits == 1
        r2 = run_enrich(
            ws, do_favicon=False, resolve=lambda _h: "1.1.1.1", lookup=lambda _ip: CYMRU_OK
        )
        assert r2.favicons == [] and r2.asn_hits == 1

    def test_no_targets_is_empty(self, tmp_path):
        ws = _ws(tmp_path)  # nothing gathered
        report = run_enrich(ws, fetch=lambda _u: b"i", resolve=lambda _h: "1.1.1.1")
        assert report.favicons == [] and report.asns == []


def test_default_fetch_rejects_non_http_scheme():
    # the scheme guard must fire before any urlopen (no file:// / ftp:// fetches)
    with pytest.raises(ValueError, match="http"):
        default_fetch("file:///etc/passwd")


# --- CLI ------------------------------------------------------------------
@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTKIT_HOME", raising=False)
    monkeypatch.setenv("HUNTKIT_GENERAL_WORKSPACE_PATH", str(tmp_path))
    monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_enrich_in_help(home):
    result = runner.invoke(app, ["--help"])
    assert "enrich" in result.stdout


def test_enrich_needs_a_program(home):
    result = runner.invoke(app, ["enrich"])
    assert result.exit_code == 2


def test_enrich_requires_one_enricher(home):
    runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
    result = runner.invoke(app, ["enrich", "-p", "acme", "--no-favicon", "--no-asn"])
    assert result.exit_code == 2
