"""Tests for the per-rule verifier registry."""

from __future__ import annotations

from huntkit.verify.client import Probe
from huntkit.verify.verifiers import VERIFIERS, confirms


def test_git_exposed_confirms_on_ref_head():
    p = Probe("http://h/.git/HEAD", 200, "ref: refs/heads/main\n", "text/plain", 21)
    assert VERIFIERS["git-exposed"].path == "/.git/HEAD"
    assert VERIFIERS["git-exposed"].confirm(p) is True


def test_git_exposed_rejects_html_404_page():
    p = Probe("http://h/.git/HEAD", 200, "<html>not found</html>", "text/html", 22)
    assert VERIFIERS["git-exposed"].confirm(p) is False


def test_env_exposed_confirms_on_key_value_lines():
    p = Probe("http://h/.env", 200, "APP_KEY=base64:abc\nDB_PASSWORD=secret\n", "text/plain", 38)
    assert VERIFIERS["env-exposed"].confirm(p) is True


def test_env_exposed_rejects_html():
    p = Probe("http://h/.env", 200, "<html><body>home</body></html>", "text/html", 30)
    assert VERIFIERS["env-exposed"].confirm(p) is False


def test_phpinfo_confirms_on_signature():
    p = Probe("http://h/phpinfo", 200, "<title>phpinfo()</title>", "text/html", 24)
    assert VERIFIERS["phpinfo"].confirm(p) is True


def test_apache_status_confirms_on_heading():
    p = Probe("http://h/server-status", 200, "<h1>Apache Server Status for h</h1>", "text/html", 35)
    assert VERIFIERS["apache-status"].confirm(p) is True


def test_admin_panel_confirms_on_auth_status():
    assert VERIFIERS["admin-panel"].confirm(Probe("http://h/admin", 401, "", "", 0)) is True
    assert VERIFIERS["admin-panel"].confirm(Probe("http://h/admin", 403, "", "", 0)) is True
    assert VERIFIERS["admin-panel"].confirm(Probe("http://h/admin", 404, "", "", 0)) is False


def test_confirms_returns_none_for_unknown_rule():
    assert confirms("reflect-param", Probe("http://h/", 200, "", "", 0)) is None


def test_confirms_delegates_to_registered_predicate():
    p = Probe("http://h/.git/HEAD", 200, "ref: refs/heads/main", "text/plain", 20)
    assert confirms("git-exposed", p) is True
