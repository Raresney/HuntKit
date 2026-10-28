"""Notify layer — push a re-sweep's delta to a chat webhook.

When a monitored program grows — a new subdomain, a freshly-live URL, above
all a *new finding* — HuntKit can ping a Slack or Discord incoming webhook so
you hear about it without watching a terminal. The POST is injectable, so the
orchestration is tested offline, and the URL is scheme-guarded to http(s).

Sending a diff to a webhook is egress of engagement data to a third party, so
it only ever happens for a webhook you pass explicitly.
"""

from __future__ import annotations

from .webhook import PostFn, default_post, notify, summarise

__all__ = ["PostFn", "default_post", "notify", "summarise"]
