"""Knowledge base — rich, per-bug-class playbooks.

A feature layer (like ``intel`` and ``pipeline``): it builds on ``utils`` but
is independent of the plugin registry and the workspace, so it stays pure,
offline, and trivially testable. The intelligence engine references these
playbook ids, and ``huntkit playbook <id>`` renders their full content.
"""

from __future__ import annotations

from .playbooks import (
    PLAYBOOKS,
    Playbook,
    Reference,
    all_playbooks,
    get_playbook,
    titles,
)

__all__ = [
    "PLAYBOOKS",
    "Playbook",
    "Reference",
    "all_playbooks",
    "get_playbook",
    "titles",
]
