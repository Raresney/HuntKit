"""Shared severity vocabulary.

One ordered :class:`Severity` enum for the whole framework: the intelligence
engine scores with it, the knowledge base tags playbooks with it, and the
reporter (phase 7) renders with it. It lives in ``utils`` — the bottom of the
dependency graph — so every feature layer shares one definition instead of
each redefining severity and drifting apart.

``.label`` / ``.style`` map straight onto the Rich theme keys in
:mod:`huntkit.utils.terminal`, so a severity colours itself consistently
wherever it is printed.
"""

from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    """Ordered so signals can be compared and aggregated numerically."""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return "informational" if self is Severity.INFO else self.name.lower()

    @property
    def style(self) -> str:  # matches the theme keys in utils.terminal
        return self.label

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        """Parse a label back into a Severity ('informational'/'info' -> INFO).

        The inverse of :attr:`label`, so severities that were serialised to
        JSON (e.g. scans/intel.json) can be read back as ordered enums.
        """
        key = name.strip().lower()
        if key in ("info", "informational"):
            return cls.INFO
        try:
            return cls[key.upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {name!r}") from None
