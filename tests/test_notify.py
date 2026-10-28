"""Webhook notify layer — message shaping, payload keys, scheme guard."""

from __future__ import annotations

import pytest

from huntkit.history import CategoryDiff, DiffReport
from huntkit.notify import default_post, notify, summarise
from huntkit.notify.webhook import _is_discord, _payload


def _report(*, added_findings=None, added_subs=None, removed_subs=None):
    cats = [
        CategoryDiff(
            name="subdomains",
            added=added_subs or [],
            removed=removed_subs or [],
        ),
        CategoryDiff(name="findings", added=added_findings or [], removed=[]),
    ]
    return DiffReport(
        program="acme",
        base_id="20260101-000000",
        base_time="2026-01-01T00:00:00Z",
        new_id="20260102-000000",
        new_time="2026-01-02T00:00:00Z",
        categories=cats,
    )


class TestSummarise:
    def test_lists_new_findings(self):
        text = summarise(_report(added_findings=["https://a.acme.com [cve] x"]))
        assert "acme" in text
        assert "NEW FINDINGS (1)" in text
        assert "https://a.acme.com [cve] x" in text

    def test_shows_added_and_removed_counts(self):
        text = summarise(
            _report(added_subs=["a.acme.com", "b.acme.com"], removed_subs=["c.acme.com"])
        )
        assert "subdomains: +2 -1" in text

    def test_caps_the_finding_list(self):
        many = [f"finding-{i}" for i in range(25)]
        text = summarise(_report(added_findings=many))
        assert "finding-0" in text
        assert "finding-9" in text
        assert "finding-10" not in text
        assert "and 15 more" in text


class TestPayload:
    def test_discord_host_detected(self):
        assert _is_discord("https://discord.com/api/webhooks/1/abc")
        assert _is_discord("https://canary.discordapp.com/api/webhooks/1/abc")
        assert not _is_discord("https://hooks.slack.com/services/T/B/x")
        # substring in a non-host position must not fool it
        assert not _is_discord("https://evil.com/?x=discord.com")

    def test_discord_uses_content_key(self):
        assert _payload("https://discord.com/api/webhooks/1/abc", "hi") == {"content": "hi"}

    def test_slack_uses_text_key(self):
        assert _payload("https://hooks.slack.com/services/x", "hi") == {"text": "hi"}


class TestNotify:
    def test_injected_post_receives_url_and_payload(self):
        seen = {}

        def fake_post(url, payload):
            seen["url"] = url
            seen["payload"] = payload
            return True

        ok = notify(
            "https://hooks.slack.com/services/x",
            _report(added_findings=["boom"]),
            post=fake_post,
        )
        assert ok is True
        assert seen["url"] == "https://hooks.slack.com/services/x"
        assert "boom" in seen["payload"]["text"]

    def test_post_failure_returns_false(self):
        assert notify("https://x", _report(added_findings=["x"]), post=lambda u, p: False) is False


class TestDefaultPost:
    def test_rejects_non_http_scheme(self):
        with pytest.raises(ValueError, match="non-http"):
            default_post("file:///etc/passwd", {"text": "x"})

    def test_rejects_scheme_less_url(self):
        with pytest.raises(ValueError):
            default_post("hooks.slack.com/x", {"text": "x"})
