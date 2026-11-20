"""Active verification of recon signals.

Recon scores potential from the shape of the surface. This package confirms
that potential with a bounded HTTP probe: it fetches the evidence a signal
points at and checks the response, so a finding is marked confirmed, dead, or
left unverified. Probing touches the target, so it runs behind the workspace
scope guard as its own phase; recon itself stays non-touching.
"""

from __future__ import annotations

__all__ = ["Probe", "probe"]

from .client import Probe, probe
