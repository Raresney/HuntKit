"""Active scanning layer.

Drives the ``SCAN``-category plugins over the URLs recon gathered, writing
findings to the workspace's ``scans/`` directory. See :mod:`huntkit.scanner.
runner` for the contract; the public surface is :func:`run_scan`.
"""

from __future__ import annotations

from .runner import (
    FINDINGS_JSON,
    Scanner,
    ScanOutcome,
    ScanSummary,
    run_scan,
    scan_plugins,
    scan_targets,
)

__all__ = [
    "FINDINGS_JSON",
    "ScanOutcome",
    "ScanSummary",
    "Scanner",
    "run_scan",
    "scan_plugins",
    "scan_targets",
]
