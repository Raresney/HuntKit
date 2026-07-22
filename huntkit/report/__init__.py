"""Reporting layer — turn a scored workspace into a shareable report.

A composition feature layer over ``intel`` and ``knowledge``: :func:`build`
assembles the :class:`~huntkit.report.builder.Report`, :mod:`render` turns it
into Markdown / HTML / JSON, and :func:`write` persists it under the
workspace's ``reports/`` directory. PDF is best-effort — with the optional
``weasyprint`` backend it renders a PDF, otherwise it writes the print-ready
HTML and says so, keeping the core dependency-light.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from ..core.workspace import Workspace
from ..utils import filesystem as fs
from ..utils.validators import sanitize_filename
from . import render
from .builder import Report, build

# Canonical output formats.
FORMATS = ("md", "html", "json", "pdf")
_ALIASES = {
    "md": "md", "markdown": "md",
    "html": "html", "htm": "html",
    "json": "json",
    "pdf": "pdf",
}


def normalise_format(fmt: str) -> str | None:
    """Map a user-supplied format onto a canonical one, or None if unknown."""
    return _ALIASES.get(fmt.strip().lower())


@dataclass
class Written:
    """Where a report landed, plus an optional note (e.g. PDF degraded to HTML)."""

    path: Path
    note: str = ""


def _default_path(ws: Workspace, ext: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return ws.path("reports", f"{sanitize_filename(ws.program)}-{stamp}.{ext}")


_RENDERERS = {
    "md": render.to_markdown,
    "html": render.to_html,
    "json": render.to_json,
}


def write(ws: Workspace, report: Report, fmt: str, out: Path | None = None) -> Written:
    """Render ``report`` as ``fmt`` (canonical) and write it to disk."""
    if fmt == "pdf":
        return _write_pdf(ws, report, out)
    target = out or _default_path(ws, fmt)
    fs.write_text(target, _RENDERERS[fmt](report))
    return Written(target)


def _write_pdf(ws: Workspace, report: Report, out: Path | None) -> Written:
    html = render.to_html(report)
    target = out or _default_path(ws, "pdf")
    try:
        import weasyprint  # type: ignore
    except Exception:
        # No PDF backend: write the print-ready HTML and tell the user.
        fallback = target.with_suffix(".html")
        fs.write_text(fallback, html)
        return Written(
            fallback,
            "no PDF backend (install `weasyprint`) — wrote print-ready HTML "
            "instead; open it and use Print → Save as PDF.",
        )
    fs.ensure_dir(target.parent)                                   # pragma: no cover
    weasyprint.HTML(string=html).write_pdf(str(target))           # pragma: no cover
    return Written(target)                                        # pragma: no cover


def generate(ws: Workspace, fmt: str = "md", out: Path | None = None) -> Written:
    """Build the report and write it in one call."""
    return write(ws, build(ws), fmt, out)


__all__ = [
    "FORMATS",
    "Report",
    "Written",
    "build",
    "generate",
    "normalise_format",
    "render",
    "write",
]
