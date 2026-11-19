"""Tests for the verification engine: baseline, scope guard, state mapping."""

from __future__ import annotations

from huntkit.intel.signals import Severity, Signal, VerifyState
from huntkit.verify.client import Probe
from huntkit.verify.engine import (
    VerifyResult,
    apply_results,
    base_for_host,
    verify_signals,
)


def _sig(rule_id: str, sev: Severity = Severity.HIGH, host: str = "h") -> Signal:
    return Signal(rule_id, "t", sev, "path", host, "e")


def _boom(url, **kwargs):  # must never be called
    raise AssertionError(f"probed {url}")


def test_base_for_host_prefers_https():
    bases = base_for_host(["http://h/a", "https://h/b", "http://x/c"])
    assert bases["h"] == "https://h"
    assert bases["x"] == "http://x"


def test_confirmed_when_predicate_matches():
    miss = Probe("", 404, "", "", 0)
    hit = {"http://h/.git/HEAD": Probe("", 200, "ref: refs/heads/main", "text/plain", 20)}
    out = verify_signals(
        [_sig("git-exposed")],
        bases={"h": "http://h"},
        in_scope=lambda h: True,
        probe_fn=lambda u, **k: hit.get(u, miss),
    )
    assert out[("h", "git-exposed")].state is VerifyState.CONFIRMED


def test_catch_all_host_is_marked_dead_even_when_predicate_would_pass():
    # Every path, including the random baseline, returns the same "login" page.
    # The predicate would confirm admin-panel on a login body, but the baseline
    # match proves the host answers everything, so the signal is dead.
    page = lambda u, **k: Probe(u, 200, "please login here", "text/html", 17)  # noqa: E731
    out = verify_signals(
        [_sig("admin-panel", Severity.MEDIUM)],
        bases={"h": "http://h"},
        in_scope=lambda h: True,
        probe_fn=page,
    )
    assert out[("h", "admin-panel")].state is VerifyState.DEAD


def test_transport_error_stays_unverified():
    out = verify_signals(
        [_sig("git-exposed")],
        bases={"h": "http://h"},
        in_scope=lambda h: True,
        probe_fn=lambda u, **k: Probe(u, 0, "", "", 0),
    )
    assert out[("h", "git-exposed")].state is VerifyState.UNVERIFIED


def test_signal_without_base_is_skipped():
    out = verify_signals([_sig("git-exposed")], bases={}, in_scope=lambda h: True, probe_fn=_boom)
    assert ("h", "git-exposed") not in out


def test_out_of_scope_host_is_never_probed():
    calls: list[str] = []

    def spy(u, **k):
        calls.append(u)
        return Probe(u, 200, "", "", 0)

    verify_signals(
        [_sig("git-exposed")], bases={"h": "http://h"}, in_scope=lambda h: False, probe_fn=spy
    )
    assert calls == []


def test_signal_without_a_verifier_is_skipped():
    out = verify_signals(
        [_sig("reflect-param", Severity.LOW)],
        bases={"h": "http://h"},
        in_scope=lambda h: True,
        probe_fn=lambda u, **k: Probe(u, 200, "x", "text/html", 1),
    )
    assert ("h", "reflect-param") not in out


def test_predicate_false_is_dead():
    miss = Probe("", 404, "", "", 0)
    html = {"http://h/.git/HEAD": Probe("", 200, "<html>404</html>", "text/html", 16)}
    out = verify_signals(
        [_sig("git-exposed")],
        bases={"h": "http://h"},
        in_scope=lambda h: True,
        probe_fn=lambda u, **k: html.get(u, miss),
    )
    assert out[("h", "git-exposed")].state is VerifyState.DEAD


def test_apply_results_sets_state_and_evidence():
    res = {("h", "git-exposed"): VerifyResult(VerifyState.CONFIRMED, "200 ref")}
    out = apply_results([_sig("git-exposed")], res)[0]
    assert out.state is VerifyState.CONFIRMED
    assert out.verified_evidence == "200 ref"


def test_apply_results_leaves_unmatched_signal_unverified():
    out = apply_results([_sig("git-exposed")], {})[0]
    assert out.state is VerifyState.UNVERIFIED
