"""Optional local-LLM advisor via Ollama.

If you have Ollama running locally, HuntKit can hand it a compact summary
of the current workspace and ask for prioritised next steps. This is fully
optional and fully local — nothing leaves the machine, and HuntKit works
without it. The static idea engine in methodology.py is the offline default.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import ui
from .workspace import Workspace

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

SYSTEM_PROMPT = (
    "You are a senior bug bounty mentor. Given recon data from an AUTHORISED "
    "engagement, suggest the 5 highest-value next actions. Be specific and "
    "reference the actual hosts/tech/URLs provided. Only suggest testing "
    "against the listed in-scope assets. Output a short numbered list."
)


def _summary(ws: Workspace, limit: int = 40) -> str:
    counts = ws.state.get("counts", {})
    scope = ws.state.get("scope", {})
    parts = [
        f"Program: {ws.program}",
        f"Scope in: {', '.join(scope.get('in', [])) or 'unspecified'}",
        f"Counts: {json.dumps(counts)}",
    ]
    tech = ws.path("recon", "httpx.txt")
    if tech.exists():
        lines = [l for l in tech.read_text(encoding="utf-8").splitlines() if l.strip()][:limit]
        parts.append("Live hosts / tech:\n" + "\n".join(lines))
    params = ws.read_lines("urls/params.txt")[:limit]
    if params:
        parts.append("Parameterised URLs:\n" + "\n".join(params))
    findings = ws.read_lines("scans/nuclei.txt")[:limit]
    if findings:
        parts.append("nuclei findings:\n" + "\n".join(findings))
    return "\n\n".join(parts)


def available(model: str = "llama3.2") -> bool:
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/tags")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def advise(ws: Workspace, model: str = "llama3.2") -> None:
    ui.banner(f"HuntKit AI advisor ({model})")
    if not available(model):
        ui.warn("Ollama not reachable on 127.0.0.1:11434.")
        ui.info("Start it with `ollama serve` and pull a model, e.g. `ollama pull llama3.2`.")
        ui.info("Offline alternative:  huntkit ideas")
        return

    prompt = f"{SYSTEM_PROMPT}\n\n--- RECON DATA ---\n{_summary(ws)}\n--- END ---\n"
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()

    ui.info("thinking (local model)...")
    try:
        req = urllib.request.Request(OLLAMA_URL, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode())
        print("\n" + data.get("response", "(no response)").strip() + "\n")
        ws.record_run("advise", model=model)
    except urllib.error.URLError as exc:
        ui.error(f"Ollama request failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        ui.error(f"advisor error: {exc}")
