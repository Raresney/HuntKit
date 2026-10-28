"""Guard the Docker packaging contract.

These don't build the image (that needs a Docker daemon and minutes of network
pulls) — they lock the invariants a silent edit could break: the image stays
multi-stage, HuntKit is the entrypoint, engagement data never gets baked in,
and the toolchain the plugins expect is actually installed.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"


def _dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def test_dockerfile_and_ignore_exist() -> None:
    assert DOCKERFILE.is_file()
    assert DOCKERIGNORE.is_file()


def test_multi_stage_build() -> None:
    # a builder stage for the Go tools, a slim runtime stage.
    froms = re.findall(r"^FROM ", _dockerfile(), flags=re.MULTILINE)
    assert len(froms) >= 2, "expected a multi-stage build"
    assert "AS builder" in _dockerfile()


def test_entrypoint_is_huntkit() -> None:
    assert 'ENTRYPOINT ["huntkit"]' in _dockerfile()


def test_installs_huntkit() -> None:
    assert "pip install" in _dockerfile()
    assert "-e ." in _dockerfile()


def test_data_volume_is_wired() -> None:
    text = _dockerfile()
    assert "HUNTKIT_HOME=/data" in text
    assert "VOLUME /data" in text


def test_go_toolchain_is_installed() -> None:
    # a representative slice of the plugins the pipeline wires in by capability.
    text = _dockerfile()
    for tool in ("subfinder", "httpx", "naabu", "nuclei", "gowitness"):
        assert tool in text, f"{tool} missing from the image"


def test_apt_native_tools_installed() -> None:
    text = _dockerfile()
    for tool in ("nmap", "whatweb", "chromium"):
        assert tool in text, f"{tool} missing from the runtime stage"


def test_dockerignore_excludes_engagement_data() -> None:
    text = DOCKERIGNORE.read_text(encoding="utf-8")
    assert ".huntkit" in text
    assert ".git" in text
