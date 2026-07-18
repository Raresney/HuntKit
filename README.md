# HuntKit

**Local bug bounty recon & methodology copilot** — a single-file-friendly Python CLI that orchestrates the standard Kali toolchain, keeps your findings organised per program, and *tells you where to dig next*.

HuntKit does not reinvent scanners. It drives the tools you already use
(subfinder, httpx, naabu, gau, nuclei, ffuf, dalfox …), stores results in a
tidy per-program workspace, and layers a **methodology + idea engine** on top
that reads your recon output and suggests specific, prioritised next steps.

> ⚠️ **Authorised testing only.** Use HuntKit against assets you own or that
> are explicitly in scope for a bug bounty program / signed engagement.
> HuntKit enforces a per-program scope list and will refuse recon on hosts you
> haven't declared in scope. You are responsible for staying within the rules.

---

## Why

When you drop into Kali for a session, the friction isn't running the tools —
it's remembering the whole chain, keeping output organised, and knowing what
to prioritise from a wall of subdomains and URLs. HuntKit is the glue:

- **Recon** — subdomains → live hosts → ports → known URLs, deduped on disk.
- **Scan** — nuclei, ffuf content discovery, arjun params, dalfox XSS.
- **Ideas** — battle-tested playbooks per bug class *plus* an engine that reads
  detected tech / URL patterns / open ports and suggests what to try.
- **Organise** — one workspace per program, activity log, markdown reports.
- **Advise (optional)** — hand a summary to a local Ollama model for extra ideas.

Zero required dependencies — pure stdlib. `rich` is optional for prettier output.

---

## Install

```bash
git clone https://github.com/Raresney/HuntKit.git
cd HuntKit

# run it directly, no install:
python3 huntkit.py doctor

# or install as a command:
pipx install .        # gives you `huntkit`
pip install .[pretty] # add rich for colour tables
```

The external tools are the usual bug bounty stack. Check what you have:

```bash
python3 huntkit.py doctor
```

Anything missing is reported with its install command; those stages are simply
skipped, so HuntKit is useful even on a fresh box.

---

## Quick start

```bash
# 1. create a workspace + declare scope
huntkit init acme -d acme.com -d "*.acme.com" -x blog.acme.com

# 2. run the full recon chain
huntkit recon acme.com -p acme

# 3. see prioritised suggestions from what recon found
huntkit ideas -p acme

# 4. scan the live hosts
huntkit scan -p acme -t nuclei

# 5. pull a full checklist for a specific bug class
huntkit ideas ssrf

# 6. write a markdown report
huntkit report -p acme
```

If you only have one workspace, `-p` is inferred, so it's just
`huntkit recon acme.com`, `huntkit ideas`, etc.

---

## Commands

| Command | What it does |
| --- | --- |
| `doctor` | Show which external tools are installed / missing. |
| `init <program> -d <domain>` | Create a workspace and set scope. |
| `recon <domain> [-s stage]` | Full chain or a single stage (`subs`/`live`/`ports`/`urls`). |
| `scan [-t type]` | `nuclei` / `xss` / `dir` / `params` / `all`. |
| `ideas [category]` | Empty = auto-suggest from recon; `list` = all playbooks; `<key>` = one checklist. |
| `advise` | Local-LLM next steps via Ollama (optional). |
| `status` | What has run in a workspace. |
| `report` | Write a markdown report to the workspace. |

Playbooks included: `idor`, `bac`, `xss`, `ssrf`, `sqli`, `ssti`,
`subtakeover`, `authn`, `cors`.

---

## How the idea engine works

After recon, `huntkit ideas` reads the workspace and cross-references:

- **Detected technology** (from httpx) → e.g. *Spring detected → check
  `/actuator/*`, SpEL SSTI*.
- **URL patterns** (from gau/wayback) → e.g. *`?url=` params → test SSRF /
  open redirect*; *`?id=` params → test IDOR*.
- **Open ports** (from naabu/nmap) → e.g. *Redis on 6379 → often unauthenticated*.
- **nuclei findings** → surfaced as confirmed leads to triage first.

It then points you at the exact playbooks worth running next. Everything is
heuristic and offline — no data leaves your machine.

---

## Workspace layout

```
~/.huntkit/<program>/
├── scope/        in/out scope lists
├── recon/        subdomains.txt, live.txt, httpx.txt, ports.txt
├── urls/         all_urls.txt, params.txt
├── scans/        nuclei.txt, ffuf_*.json, dalfox.txt
├── notes/        your own notes
├── loot/         confirmed findings
├── reports/      generated markdown
└── state.json    counts + activity log
```

Override the base dir with `-w <dir>` or the `HUNTKIT_HOME` env var. Workspace
data is gitignored — never commit engagement data.

---

## License

MIT — see [LICENSE](LICENSE).
