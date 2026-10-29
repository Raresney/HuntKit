"""Guard the demo asset and its README embed.

The demo SVG is a self-contained terminal cast (renders inline on GitHub, both
themes, no external deps). These lock that it stays valid, self-contained, and
actually referenced from the README.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "docs" / "demo.svg"
README = ROOT / "README.md"


def test_demo_svg_exists_and_parses() -> None:
    assert DEMO.is_file()
    root = ET.fromstring(DEMO.read_text(encoding="utf-8"))
    assert root.tag.endswith("svg")


def test_demo_is_self_contained() -> None:
    # no external resources, no scripts — GitHub would strip them anyway.
    # (the SVG xmlns is http://www.w3.org/2000/svg; that's a namespace, not a
    # fetch, so we check for actual references instead.)
    text = DEMO.read_text(encoding="utf-8").lower()
    assert "<script" not in text
    assert "<image" not in text
    assert "href" not in text
    assert "url(" not in text


def test_demo_shows_the_headline_commands() -> None:
    text = DEMO.read_text(encoding="utf-8")
    for cmd in ("recon", "scan", "analyze", "report", "monitor", "dashboard"):
        assert cmd in text, f"demo omits {cmd}"
    assert "0.3.0" in text


def test_readme_embeds_the_demo() -> None:
    assert "docs/demo.svg" in README.read_text(encoding="utf-8")
