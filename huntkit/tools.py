"""External tool registry and runner.

HuntKit does not reimplement scanners; it orchestrates the standard
bug-bounty toolchain. Every tool is declared here with the command used
to detect it and a hint for installing it, so `huntkit doctor` can report
exactly what is missing before a run starts.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Tool:
    name: str            # binary name / key
    purpose: str         # short human description
    install: str         # how to get it
    category: str        # recon | scan | resolve | urls

    @property
    def path(self) -> Optional[str]:
        return shutil.which(self.name)

    @property
    def installed(self) -> bool:
        return self.path is not None


# The toolchain HuntKit knows how to drive. Ordered by preference within a
# category so the orchestrator can pick the first installed option.
REGISTRY: dict[str, Tool] = {
    # --- subdomain / asset discovery ---
    "subfinder": Tool("subfinder", "Passive subdomain enumeration",
                       "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                       "recon"),
    "assetfinder": Tool("assetfinder", "Passive subdomain discovery",
                        "go install github.com/tomnomnom/assetfinder@latest", "recon"),
    "amass": Tool("amass", "In-depth DNS/asset enumeration",
                  "sudo apt install amass  # or: go install ...owasp-amass/amass/v4/...@master",
                  "recon"),
    # --- live host / tech ---
    "httpx": Tool("httpx", "Probe live hosts, titles, tech, status codes",
                  "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "resolve"),
    "whatweb": Tool("whatweb", "Technology fingerprinting",
                    "sudo apt install whatweb", "resolve"),
    # --- ports ---
    "naabu": Tool("naabu", "Fast SYN/CONNECT port scanner",
                  "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "recon"),
    "nmap": Tool("nmap", "Port scan + service/version detection",
                 "sudo apt install nmap", "recon"),
    # --- url gathering ---
    "gau": Tool("gau", "Fetch known URLs from wayback/otx/commoncrawl",
                "go install github.com/lc/gau/v2/cmd/gau@latest", "urls"),
    "waybackurls": Tool("waybackurls", "Fetch URLs from the Wayback Machine",
                        "go install github.com/tomnomnom/waybackurls@latest", "urls"),
    "katana": Tool("katana", "Active crawler / URL discovery",
                   "go install github.com/projectdiscovery/katana/cmd/katana@latest", "urls"),
    # --- vuln / fuzz ---
    "nuclei": Tool("nuclei", "Template-based vulnerability scanner",
                   "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "scan"),
    "ffuf": Tool("ffuf", "Content/vhost/parameter fuzzing",
                 "go install github.com/ffuf/ffuf/v2@latest", "scan"),
    "arjun": Tool("arjun", "HTTP parameter discovery",
                  "pipx install arjun  # or: pip install arjun", "scan"),
    "dalfox": Tool("dalfox", "XSS scanning / parameter analysis",
                   "go install github.com/hahwul/dalfox/v2@latest", "scan"),
}


def get(name: str) -> Tool:
    return REGISTRY[name]


def first_installed(*names: str) -> Optional[Tool]:
    """Return the first installed tool among `names`, preserving order."""
    for name in names:
        tool = REGISTRY.get(name)
        if tool and tool.installed:
            return tool
    return None


class ToolResult:
    def __init__(self, code: int, stdout: str, stderr: str, cmd: list[str]):
        self.code = code
        self.stdout = stdout
        self.stderr = stderr
        self.cmd = cmd

    @property
    def ok(self) -> bool:
        return self.code == 0

    @property
    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]


def run(cmd: list[str], *, timeout: Optional[int] = None,
        stdin_data: Optional[str] = None, check: bool = False) -> ToolResult:
    """Run an external command and capture output.

    Never raises on non-zero exit unless `check=True`; recon tooling
    routinely returns non-zero when a source is empty, and that should not
    abort the whole run.
    """
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return ToolResult(127, "", f"binary not found: {cmd[0]}", cmd)
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return ToolResult(124, partial, f"timeout after {timeout}s", cmd)

    result = ToolResult(proc.returncode, proc.stdout, proc.stderr, cmd)
    if check and not result.ok:
        raise RuntimeError(f"command failed ({result.code}): {' '.join(cmd)}\n{result.stderr}")
    return result


def python_module_available(module: str) -> bool:
    try:
        __import__(module)
        return True
    except Exception:
        return False
