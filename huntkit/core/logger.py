"""Structured logging built on Rich.

Console logging is human-friendly; an optional rotating file handler writes a
full engagement log into the workspace `logs/` directory. Feature modules
call `get_logger(__name__)` and never touch handler configuration.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from rich.logging import RichHandler

from ..utils.terminal import console

_CONFIGURED = False
_ROOT = "huntkit"


def setup_logging(
    level: str = "INFO",
    logfile: Optional[Path] = None,
    *,
    verbose: bool = False,
) -> None:
    """Configure the `huntkit` logger tree once.

    Safe to call repeatedly (e.g. after a workspace is opened to attach a
    file handler) — handlers are reset rather than duplicated.
    """
    global _CONFIGURED
    logger = logging.getLogger(_ROOT)
    logger.setLevel(logging.DEBUG if verbose else getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    logger.propagate = False

    rich_handler = RichHandler(
        console=console,
        show_time=verbose,
        show_path=verbose,
        rich_tracebacks=True,
        markup=True,
    )
    rich_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(rich_handler)

    if logfile is not None:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(logfile, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(file_handler)

    _CONFIGURED = True


def get_logger(name: str = _ROOT) -> logging.Logger:
    if not _CONFIGURED:
        setup_logging()
    if name == _ROOT or name.startswith(_ROOT + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{_ROOT}.{name}")
