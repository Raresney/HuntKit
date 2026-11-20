"""Confirm signals against the live target, one bounded probe at a time.

For each in-scope host with a live http(s) base, the engine first probes a
random path to learn what a miss looks like (the soft-404 baseline), then probes
each signal whose rule carries a verifier. A probe that matches the baseline is
dead even when its predicate would otherwise pass, which is how a catch-all host
is caught. A transport error leaves the signal unverified rather than dead.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from ..intel.signals import Signal, VerifyState
from .client import Probe, probe
from .verifiers import VERIFIERS, confirms

ProbeFn = Callable[..., Probe]


@dataclass(frozen=True)
class VerifyResult:
    state: VerifyState
    evidence: str


def base_for_host(live_urls: list[str]) -> dict[str, str]:
    """Map each host to one base origin, preferring https over http."""
    bases: dict[str, str] = {}
    for raw in live_urls:
        url = raw.strip()
        if not url:
            continue
        parts = urlsplit(url if "://" in url else "//" + url, scheme="http")
        host = (parts.hostname or "").lower()
        if not host:
            continue
        scheme = parts.scheme.lower() if parts.scheme in ("http", "https") else "http"
        authority = host + (f":{parts.port}" if parts.port else "")
        origin = f"{scheme}://{authority}"
        if host not in bases or (scheme == "https" and bases[host].startswith("http://")):
            bases[host] = origin
    return bases


def _body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()


def _matches_baseline(p: Probe, baseline: Probe) -> bool:
    """True when the probe looks like the host's miss response (catch-all)."""
    if baseline.status == 0:
        return False
    return p.status == baseline.status and _body_hash(p.body) == _body_hash(baseline.body)


def _evidence(p: Probe) -> str:
    snippet = " ".join(p.body.split())[:80]
    return f"{p.status} {snippet}".strip()


def verify_signals(
    signals: list[Signal],
    *,
    bases: dict[str, str],
    in_scope: Callable[[str], bool],
    probe_fn: ProbeFn = probe,
    delay: float = 0.0,
    **probe_kwargs: object,
) -> dict[tuple[str, str], VerifyResult]:
    """Probe every signal that has a verifier; return results keyed by (host, id)."""
    by_host: dict[str, list[Signal]] = defaultdict(list)
    for sig in signals:
        if sig.id in VERIFIERS:
            by_host[sig.host].append(sig)

    results: dict[tuple[str, str], VerifyResult] = {}
    for host, host_signals in by_host.items():
        base = bases.get(host)
        if base is None or not in_scope(host):
            continue
        baseline = probe_fn(f"{base}/{secrets.token_hex(8)}", **probe_kwargs)
        if delay > 0:
            time.sleep(delay)
        for sig in host_signals:
            verifier = VERIFIERS[sig.id]
            p = probe_fn(base + verifier.path, **probe_kwargs)
            if p.status == 0:
                state = VerifyState.UNVERIFIED
            elif _matches_baseline(p, baseline):
                state = VerifyState.DEAD
            else:
                verdict = confirms(sig.id, p)
                if verdict is True:
                    state = VerifyState.CONFIRMED
                elif verdict is False:
                    state = VerifyState.DEAD
                else:  # inconclusive predicate: a lead, not a kill
                    state = VerifyState.UNVERIFIED
            results[(host, sig.id)] = VerifyResult(state, _evidence(p))
            if delay > 0:
                time.sleep(delay)
    return results


def apply_results(
    signals: list[Signal], results: dict[tuple[str, str], VerifyResult]
) -> list[Signal]:
    """Return signals with verification state applied; unmatched ones unchanged."""
    out: list[Signal] = []
    for sig in signals:
        result = results.get((sig.host, sig.id))
        if result is None:
            out.append(sig)
        else:
            out.append(replace(sig, state=result.state, verified_evidence=result.evidence))
    return out
