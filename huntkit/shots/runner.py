r"""Screenshots — capture a visual of every live URL for triage and the report.

A wall of screenshots is how a hunter eyeballs a large surface fast: default
landing pages, login portals, stack-trace error screens, and abandoned admin
panels all jump out of a grid in a way a list of URLs never does. This layer
drives a headless screenshotter (``gowitness`` by default) over the live URLs
recon gathered and records a manifest the report turns into a gallery.

It follows the scanner's shape: targets are read from the workspace's own,
already scope-filtered result files *and* re-checked against scope here, so the
camera never points at a host recon would have refused. The actual capture is
injected (``CaptureFn``) so the orchestration — target collection, the
manifest, scope enforcement — is tested without a browser or ``gowitness`` on
the box.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from ..core.config import Config
from ..core.runner import CommandRunner
from ..core.workspace import Workspace

# Where captures land (under reports/ so a self-contained report can embed
# them) and where the manifest is written.
SHOTS_DIR = "reports/shots"
SHOTS_JSON = "scans/screenshots.json"
SHOTS_STATE = "shots"
TARGET_FILES = ["recon/live.txt", "urls/urls.txt"]

# A capture backend: given the URLs and an output directory, take the shots and
# return a mapping of url -> produced image filename (basename within the dir).
# Any URL left out of the mapping is reported as not captured.
CaptureFn = Callable[[list[str], Path], dict[str, str]]

EventFn = Callable[[dict], None]


@dataclass
class Shot:
    url: str
    file: str = ""  # path relative to the workspace root, or "" if not captured
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.file)

    def to_dict(self) -> dict:
        return {"url": self.url, "file": self.file, "error": self.error}


@dataclass
class ShotSummary:
    program: str
    targets: int = 0
    shots: list[Shot] = field(default_factory=list)

    @property
    def captured(self) -> int:
        return sum(1 for s in self.shots if s.ok)


def shot_targets(ws: Workspace) -> list[str]:
    """Candidate URLs from the workspace, deduped and scope-checked."""
    seen: dict[str, None] = {}
    for rel in TARGET_FILES:
        for url in ws.read_lines(rel):
            host = _host_of(url)
            if host and ws.in_scope(host):
                seen[url] = None
    return sorted(seen)


def _host_of(url: str) -> Optional[str]:
    parsed = urlparse(url if "://" in url else f"//{url}", scheme="http")
    return parsed.hostname


def run_shots(
    ws: Workspace,
    config: Config,
    *,
    runner: Optional[CommandRunner] = None,
    capture: Optional[CaptureFn] = None,
    on_event: Optional[EventFn] = None,
) -> ShotSummary:
    """Capture the live URLs and write ``scans/screenshots.json``."""
    emit: EventFn = on_event or (lambda _e: None)
    runner = runner or CommandRunner(config)
    capture = capture or gowitness_capture(runner)

    targets = shot_targets(ws)
    summary = ShotSummary(program=ws.program, targets=len(targets))
    ws.state.start(SHOTS_STATE)
    emit({"event": "shots_start", "targets": len(targets)})

    if not targets:
        ws.state.skip(SHOTS_STATE)
        emit({"event": "shots_done", "captured": 0})
        return summary

    outdir = Path(ws.path(SHOTS_DIR))
    outdir.mkdir(parents=True, exist_ok=True)
    try:
        produced = capture(targets, outdir)
    except Exception as exc:  # noqa: BLE001 — a backend crash is recorded, not raised
        ws.state.skip(SHOTS_STATE)
        emit({"event": "shots_error", "reason": str(exc) or type(exc).__name__})
        return summary

    for url in targets:
        name = produced.get(url)
        if name:
            summary.shots.append(Shot(url=url, file=f"{SHOTS_DIR}/{name}"))
        else:
            summary.shots.append(Shot(url=url, error="not captured"))

    _persist(ws, summary)
    ws.state.done(SHOTS_STATE, targets=len(targets), captured=summary.captured)
    emit({"event": "shots_done", "captured": summary.captured})
    return summary


def _persist(ws: Workspace, summary: ShotSummary) -> None:
    payload = {
        "program": summary.program,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dir": SHOTS_DIR,
        "shots": [s.to_dict() for s in summary.shots if s.ok],
    }
    ws.path(SHOTS_JSON).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def gowitness_capture(runner: CommandRunner) -> CaptureFn:
    """A :data:`CaptureFn` backed by ``gowitness`` (best-effort, version-tolerant).

    gowitness is driven over a URL list into ``outdir``; afterwards the
    directory is scanned for the images it produced and each is paired with the
    URL whose host appears in its filename, falling back to positional order
    when the counts line up. The whole capture is skipped cleanly when the
    binary is absent, so a box without gowitness still runs the rest of HuntKit.
    """

    def capture(urls: list[str], outdir: Path) -> dict[str, str]:  # pragma: no cover
        if not runner.available("gowitness"):
            return {}
        listing = outdir / "_targets.txt"
        listing.write_text("\n".join(urls) + "\n", encoding="utf-8")
        # gowitness v3: `scan file -f <list> -s <screenshot-dir> --write-none`
        runner.run(
            "gowitness",
            ["scan", "file", "-f", str(listing), "-s", str(outdir), "--write-none"],
        )
        return _pair_images(urls, outdir)

    return capture


def _pair_images(urls: list[str], outdir: Path) -> dict[str, str]:  # pragma: no cover
    """Pair produced image files to the URLs that made them (best effort)."""
    images = sorted(
        (p for p in outdir.iterdir() if p.suffix.lower() in (".png", ".jpeg", ".jpg")),
        key=lambda p: p.stat().st_mtime,
    )
    names = [p.name for p in images]
    out: dict[str, str] = {}
    unmatched = list(names)
    for url in urls:
        host = _host_of(url) or ""
        hit = next((n for n in unmatched if host and host.replace(".", "-") in n), None)
        hit = hit or next((n for n in unmatched if host and host in n), None)
        if hit:
            out[url] = hit
            unmatched.remove(hit)
    # positional fallback only when nothing matched by name but counts align
    if not out and len(names) == len(urls):
        out = dict(zip(urls, names, strict=True))
    return out
