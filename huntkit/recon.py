"""Recon orchestration: subdomains -> live hosts -> ports -> urls.

Each stage picks the best installed tool, writes deduped output into the
workspace, and skips gracefully when no suitable tool is present. Nothing
here touches a target that is out of the workspace scope.
"""

from __future__ import annotations

from . import tools, ui
from .workspace import Workspace


def enum_subdomains(ws: Workspace, domain: str, timeout: int = 300) -> list[str]:
    ui.step(f"Subdomain enumeration: {domain}")
    found: set[str] = set()

    sf = tools.get("subfinder")
    if sf.installed:
        ui.info("running subfinder (passive)")
        r = tools.run([sf.name, "-d", domain, "-silent"], timeout=timeout)
        found.update(r.lines)
    af = tools.get("assetfinder")
    if af.installed:
        ui.info("running assetfinder")
        r = tools.run([af.name, "--subs-only", domain], timeout=timeout)
        found.update(ln for ln in r.lines if ln.endswith(domain))

    if not found and not (sf.installed or af.installed):
        ui.warn("no subdomain tool installed — add the seed host only")
        found.add(domain)

    # never let out-of-scope hosts into the set
    found = {h for h in found if ws.in_scope(h)}
    added = ws.append_unique("recon/subdomains.txt", found)
    total = len(ws.read_lines("recon/subdomains.txt"))
    ws.set_count("subdomains", total)
    ws.record_run("subdomains", domain, added=added, total=total)
    ui.ok(f"{total} subdomains ({added} new)")
    return sorted(found)


def probe_live(ws: Workspace, timeout: int = 300) -> list[str]:
    ui.step("Probing live hosts")
    hosts = ws.read_lines("recon/subdomains.txt")
    if not hosts:
        ui.warn("no subdomains yet — run recon first")
        return []

    httpx = tools.get("httpx")
    if not httpx.installed:
        ui.warn("httpx not installed — cannot probe; treating all as candidates")
        ws.append_unique("recon/live.txt", [f"http://{h}" for h in hosts])
        return ws.read_lines("recon/live.txt")

    ui.info(f"probing {len(hosts)} hosts with httpx")
    # -json would be richer; keep it simple & greppable here
    r = tools.run(
        [httpx.name, "-silent", "-status-code", "-title", "-tech-detect", "-no-color"],
        stdin_data="\n".join(hosts),
        timeout=timeout,
    )
    ws.path("recon", "httpx.txt").write_text(r.stdout, encoding="utf-8")
    live_urls = [ln.split()[0] for ln in r.lines if ln.strip()]
    added = ws.append_unique("recon/live.txt", live_urls)
    total = len(ws.read_lines("recon/live.txt"))
    ws.set_count("live", total)
    ws.record_run("live", detail=f"{total} live", added=added, total=total)
    ui.ok(f"{total} live hosts ({added} new)")
    return live_urls


def scan_ports(ws: Workspace, top_ports: int = 1000, timeout: int = 600) -> None:
    ui.step("Port scanning")
    hosts = ws.read_lines("recon/subdomains.txt")
    if not hosts:
        ui.warn("no hosts to scan")
        return

    naabu = tools.get("naabu")
    if naabu.installed:
        ui.info(f"running naabu (top {top_ports} ports)")
        r = tools.run(
            [naabu.name, "-silent", "-top-ports", str(top_ports)],
            stdin_data="\n".join(hosts),
            timeout=timeout,
        )
        ws.path("recon", "ports.txt").write_text(r.stdout, encoding="utf-8")
        ws.record_run("ports", f"naabu top-{top_ports}", results=len(r.lines))
        ui.ok(f"{len(r.lines)} open host:port pairs -> recon/ports.txt")
        return

    nmap = tools.get("nmap")
    if nmap.installed:
        ui.info("naabu missing; falling back to nmap (slower)")
        out = ws.path("recon", "nmap")
        tools.run([nmap.name, "-iL", str(ws.path("recon", "subdomains.txt")),
                   "--top-ports", str(top_ports), "-oA", str(out)], timeout=timeout)
        ws.record_run("ports", "nmap fallback")
        ui.ok(f"nmap output -> recon/nmap.*")
        return

    ui.warn("no port scanner installed (naabu/nmap) — skipping")


def gather_urls(ws: Workspace, domain: str, timeout: int = 300) -> None:
    ui.step("Gathering known URLs")
    all_urls: set[str] = set()

    gau = tools.get("gau")
    if gau.installed:
        ui.info("running gau")
        r = tools.run([gau.name, "--subs", domain], timeout=timeout)
        all_urls.update(r.lines)
    wb = tools.get("waybackurls")
    if wb.installed and not all_urls:
        ui.info("running waybackurls")
        r = tools.run([wb.name, domain], timeout=timeout)
        all_urls.update(r.lines)

    if not all_urls:
        ui.warn("no url-gathering tool installed (gau/waybackurls) — skipping")
        return

    added = ws.append_unique("urls/all_urls.txt", all_urls)
    _extract_params(ws)
    total = len(ws.read_lines("urls/all_urls.txt"))
    ws.set_count("urls", total)
    ws.record_run("urls", domain, added=added, total=total)
    ui.ok(f"{total} URLs ({added} new); parameterised URLs -> urls/params.txt")


def _extract_params(ws: Workspace) -> None:
    """Split out URLs that carry query parameters — the interesting ones."""
    urls = ws.read_lines("urls/all_urls.txt")
    params = [u for u in urls if "?" in u and "=" in u]
    ws.append_unique("urls/params.txt", params)


def full(ws: Workspace, domain: str) -> None:
    """Run the whole recon chain end to end."""
    ui.banner(f"HuntKit recon — {domain}")
    enum_subdomains(ws, domain)
    probe_live(ws)
    scan_ports(ws)
    gather_urls(ws, domain)
    ui.ok("recon complete — see `huntkit status` and `huntkit ideas`")
