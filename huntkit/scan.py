"""Vulnerability & fuzzing stage: nuclei, ffuf, arjun, dalfox.

Runs against the live hosts / URLs already discovered by the recon stage.
Output lands in the workspace `scans/` directory.
"""

from __future__ import annotations

from pathlib import Path

from . import tools, ui
from .workspace import Workspace

DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]


def _pick_wordlist(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    for wl in DEFAULT_WORDLISTS:
        if Path(wl).exists():
            return wl
    return None


def nuclei_scan(ws: Workspace, severity: str = "low,medium,high,critical",
                timeout: int = 1800) -> None:
    ui.step("nuclei vulnerability scan")
    nuclei = tools.get("nuclei")
    if not nuclei.installed:
        ui.warn(f"nuclei not installed — {nuclei.install}")
        return

    live = ws.read_lines("recon/live.txt")
    if not live:
        ui.warn("no live hosts — run recon first")
        return

    out = ws.path("scans", "nuclei.txt")
    ui.info(f"scanning {len(live)} hosts (severity: {severity})")
    r = tools.run(
        [nuclei.name, "-silent", "-severity", severity, "-o", str(out), "-no-color"],
        stdin_data="\n".join(live),
        timeout=timeout,
    )
    findings = ws.read_lines("scans/nuclei.txt")
    ws.set_count("nuclei_findings", len(findings))
    ws.record_run("nuclei", severity, findings=len(findings))
    if findings:
        ui.ok(f"{len(findings)} nuclei findings -> scans/nuclei.txt")
        for f in findings[:10]:
            ui.bullet(f, "yellow")
        if len(findings) > 10:
            ui.info(f"... and {len(findings) - 10} more")
    else:
        ui.ok("nuclei finished — no findings at this severity")
    if r.code == 124:
        ui.warn("nuclei hit the time budget; results may be partial")


def dir_fuzz(ws: Workspace, target: str, wordlist: str | None = None,
             extensions: str | None = None, timeout: int = 900) -> None:
    ui.step(f"Content discovery (ffuf): {target}")
    ffuf = tools.get("ffuf")
    if not ffuf.installed:
        ui.warn(f"ffuf not installed — {ffuf.install}")
        return

    wl = _pick_wordlist(wordlist)
    if not wl:
        ui.warn("no wordlist found — pass --wordlist or install seclists")
        return

    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
    out = ws.path("scans", f"ffuf_{safe}.json")
    url = target.rstrip("/") + "/FUZZ"
    cmd = [ffuf.name, "-u", url, "-w", wl, "-mc", "200,204,301,302,307,401,403",
           "-of", "json", "-o", str(out), "-s"]
    if extensions:
        cmd += ["-e", extensions]
    ui.info(f"fuzzing {url} with {Path(wl).name}")
    tools.run(cmd, timeout=timeout)
    ws.record_run("ffuf", target, wordlist=wl)
    ui.ok(f"ffuf output -> scans/ffuf_{safe}.json")


def find_params(ws: Workspace, target: str, timeout: int = 600) -> None:
    ui.step(f"Parameter discovery (arjun): {target}")
    arjun = tools.get("arjun")
    if not arjun.installed:
        ui.warn(f"arjun not installed — {arjun.install}")
        return
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
    out = ws.path("scans", f"arjun_{safe}.json")
    tools.run([arjun.name, "-u", target, "-oJ", str(out)], timeout=timeout)
    ws.record_run("arjun", target)
    ui.ok(f"arjun output -> scans/arjun_{safe}.json")


def xss_scan(ws: Workspace, timeout: int = 1200) -> None:
    ui.step("XSS scan (dalfox) on parameterised URLs")
    dalfox = tools.get("dalfox")
    if not dalfox.installed:
        ui.warn(f"dalfox not installed — {dalfox.install}")
        return
    params = ws.read_lines("urls/params.txt")
    if not params:
        ui.warn("no parameterised URLs — run `huntkit recon` url stage first")
        return
    out = ws.path("scans", "dalfox.txt")
    ui.info(f"testing {len(params)} parameterised URLs")
    tools.run([dalfox.name, "pipe", "-o", str(out)],
              stdin_data="\n".join(params), timeout=timeout)
    ws.record_run("dalfox", detail=f"{len(params)} urls")
    ui.ok("dalfox output -> scans/dalfox.txt")
