"""Intelligence layer — turn recon output into scored, prioritised leads.

The engine reads a workspace's recon artifacts, runs them through a declarative
:mod:`~huntkit.intel.signals` catalog, scores each host, and rolls the signals
up into prioritised attack paths. It's a feature layer (like the pipeline):
it builds on ``core`` and ``utils`` but is independent of the plugin registry,
so it stays pure and easy to test.
"""

from __future__ import annotations

from .engine import (
    AttackPath,
    HostIntel,
    IntelReport,
    Priority,
    analyze,
    save_report,
)
from .signals import (
    Rule,
    Severity,
    Signal,
    scan_signals,
    signals_from_labels,
    signals_from_params,
    signals_from_paths,
    signals_from_ports,
)

__all__ = [
    "AttackPath",
    "HostIntel",
    "IntelReport",
    "Priority",
    "Rule",
    "Severity",
    "Signal",
    "analyze",
    "save_report",
    "scan_signals",
    "signals_from_labels",
    "signals_from_params",
    "signals_from_paths",
    "signals_from_ports",
]
