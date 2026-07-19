from huntkit.utils import validators as v


class TestDomain:
    def test_valid_domains(self):
        assert v.is_domain("example.com")
        assert v.is_domain("api.example.com")
        assert v.is_domain("a.b.c.example.co.uk")

    def test_invalid_domains(self):
        assert not v.is_domain("example")
        assert not v.is_domain("-bad.example.com")
        assert not v.is_domain("bad-.example.com")
        assert not v.is_domain("http://example.com")
        assert not v.is_domain("example.com/path")
        assert not v.is_domain("")

    def test_normalise_strips_scheme_port_path(self):
        assert v.normalise_domain("https://Example.com:443/foo?x=1") == "example.com"
        assert v.normalise_domain("HTTP://API.example.com/") == "api.example.com"

    def test_normalise_rejects_junk(self):
        import pytest

        with pytest.raises(v.ValidationError):
            v.normalise_domain("not a domain")


class TestWildcardAndScope:
    def test_wildcard(self):
        assert v.is_wildcard("*.example.com")
        assert not v.is_wildcard("example.com")
        assert not v.is_wildcard("*.com")  # needs 2+ labels after *

    def test_scope_entries(self):
        assert v.is_scope_entry("example.com")
        assert v.is_scope_entry("*.example.com")
        assert v.is_scope_entry("10.0.0.1")
        assert v.is_scope_entry("10.0.0.0/24")
        assert not v.is_scope_entry("nonsense")

    def test_risky_wildcard_detection(self):
        assert v.is_wildcard_scope_risky(["*.example.com"])
        assert not v.is_wildcard_scope_risky(["example.com"])


class TestUrl:
    def test_valid(self):
        assert v.is_url("https://example.com")
        assert v.is_url("http://example.com/a/b?c=d")

    def test_invalid(self):
        assert not v.is_url("ftp://example.com")
        assert not v.is_url("example.com")
        assert not v.is_url("javascript:alert(1)")


class TestSanitizeFilename:
    def test_basic(self):
        assert v.sanitize_filename("acme corp") == "acme_corp"

    def test_path_traversal_blocked(self):
        out = v.sanitize_filename("../../etc/passwd")
        assert "/" not in out and "\\" not in out and ".." not in out

    def test_empty_falls_back(self):
        assert v.sanitize_filename("///") == "default"
        assert v.sanitize_filename("..") == "default"

    def test_collapses_underscores(self):
        assert v.sanitize_filename("a$$$b") == "a_b"

    def test_truncates(self):
        assert len(v.sanitize_filename("x" * 500, max_len=50)) == 50
