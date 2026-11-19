"""Per-rule verifiers: where to probe, and what a live response looks like.

A verifier pairs a canonical request path with a predicate over the response.
Only rules whose liveness can be confirmed cheaply carry one; every other rule
id is absent, which leaves its signals unverified rather than wrongly judged.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .client import Probe

_ENV_LINE = re.compile(r"(?m)^[A-Z][A-Z0-9_]*=")


def _is_html(probe: Probe) -> bool:
    if "html" in probe.content_type.lower():
        return True
    return probe.body.lstrip()[:1] == "<"


def _git_head(p: Probe) -> bool:
    return p.status == 200 and not _is_html(p) and p.body.lstrip().startswith("ref: ")


def _svn_wc_db(p: Probe) -> bool:
    return p.status == 200 and p.body.startswith("SQLite format 3")


def _env_file(p: Probe) -> bool:
    return p.status == 200 and not _is_html(p) and bool(_ENV_LINE.search(p.body))


def _phpinfo(p: Probe) -> bool:
    return p.status == 200 and "phpinfo()" in p.body


def _apache_status(p: Probe) -> bool:
    return p.status == 200 and "Apache Server Status" in p.body


def _actuator(p: Probe) -> bool:
    if p.status != 200 or "json" not in p.content_type.lower():
        return False
    return '"_links"' in p.body or '"status"' in p.body or '"diskSpace"' in p.body


def _auth_surface(p: Probe) -> bool:
    """A privileged path is confirmed by an auth challenge or a login form."""
    if p.status in (401, 403):
        return True
    if p.status == 200:
        low = p.body.lower()
        return "<form" in low or "login" in low or "password" in low
    return False


@dataclass(frozen=True)
class Verifier:
    """A canonical probe path (host-relative) and a response predicate."""

    path: str
    confirm: Callable[[Probe], bool]
    method: str = "GET"


VERIFIERS: dict[str, Verifier] = {
    "git-exposed": Verifier("/.git/HEAD", _git_head),
    "svn-exposed": Verifier("/.svn/wc.db", _svn_wc_db),
    "env-exposed": Verifier("/.env", _env_file),
    "phpinfo": Verifier("/phpinfo", _phpinfo),
    "apache-status": Verifier("/server-status", _apache_status),
    "spring-actuator": Verifier("/actuator", _actuator),
    "phpmyadmin": Verifier("/phpmyadmin", _auth_surface),
    "adminer": Verifier("/adminer", _auth_surface),
    "admin-panel": Verifier("/admin", _auth_surface),
    "internal-path": Verifier("/internal", _auth_surface),
}


def confirms(rule_id: str, probe: Probe) -> bool | None:
    """Predicate result for a rule, or None when the rule has no verifier."""
    verifier = VERIFIERS.get(rule_id)
    if verifier is None:
        return None
    return verifier.confirm(probe)
