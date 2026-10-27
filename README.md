# HuntKit

[![CI](https://github.com/Raresney/HuntKit/actions/workflows/ci.yml/badge.svg)](https://github.com/Raresney/HuntKit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-blue)
![Coverage](https://img.shields.io/badge/coverage-93%25-brightgreen)

**Local-first bug-bounty recon, methodology & workflow framework for _authorised_ testing.**

HuntKit drives the bug-bounty toolchain you already use (subfinder, httpx, naabu,
gau, nuclei, ffuf, dalfox, …), keeps every engagement in a tidy per-program
workspace, then **reasons over what it found** — scoring the attack surface,
pointing you at the right playbooks, and writing a shareable report. Everything
is offline and on your machine; the only time data can leave is a cloud-AI call
you explicitly approve.

> ⚠️ **Authorised testing only.** Use HuntKit against assets you own or that are
> explicitly in scope for a bug-bounty program or signed engagement. It enforces
> a per-program scope list and refuses recon on hosts you haven't declared in
> scope. You are responsible for staying within the rules.

---

## Highlights

- **Parallel, resumable recon pipeline** — `subdomains → resolve → live → ports → urls`,
  running every available tool in each wave concurrently, deduped on disk, with
  stage resume and an opt-in content-addressed cache.
- **Pluggable toolchain** — each external tool is one file in `huntkit/plugins/`.
  Adding a tool is dropping a file; the pipeline wires it in by capability.
- **Intelligence engine** — turns recon output into scored, prioritised hosts and
  **attack paths** (which bug class to run, and where), from a declarative signal
  catalog. Pure and offline — it never touches the target.
- **Knowledge base** — full playbooks for 9 bug classes (detection, payloads,
  bypasses, tools, references), cross-linked from the attack paths.
- **Reporting** — one model rendered to Markdown, a self-contained HTML page, or
  JSON (PDF when `weasyprint` is present, else print-ready HTML).
- **AI advisor (optional)** — hand the scored surface to a local Ollama model, or
  a cloud model (Claude/OpenAI) **only after an explicit approval prompt that
  shows exactly what will be sent**.
- **Content scanners** — a redacting secret & JS-endpoint scanner, and a
  header-based CDN/WAF/cloud/tech fingerprinter.

---

## Install

Requires **Python 3.10+**. Runtime deps are light: `typer`, `rich`, `pyyaml`.

```bash
git clone https://github.com/Raresney/HuntKit.git
cd HuntKit
pip install -e .            # or: pipx install .

# run it:
python -m huntkit doctor
```

The external tools are the usual bug-bounty stack. `doctor` shows what you have;
anything missing is reported with its install hint and that stage is simply
skipped, so HuntKit is useful even on a fresh box.

---

## Quick start

```bash
# 1. create a workspace + declare scope
python -m huntkit init acme -s "*.acme.com" -x blog.acme.com

# 2. run the recon pipeline
python -m huntkit recon acme.com -p acme

# 3. score the surface into prioritised hosts + attack paths
python -m huntkit analyze -p acme

# 4. pull a full playbook for a bug class the analysis points at
python -m huntkit playbook ssrf

# 5. write a shareable report
python -m huntkit report -p acme -f html

# 6. (optional) ask a local LLM to prioritise it
python -m huntkit advise -p acme --provider ollama
```

With a single workspace, `-p` is inferred.

---

## Commands

| Command | What it does |
| --- | --- |
| `doctor` | Show which external tools are installed / missing, and where data lives. |
| `init <program> -s <scope>` | Create a workspace and set in/out scope (`*.wildcards` ok). |
| `recon <domain> [--stage] [--threads] [--fresh] [--no-cache]` | Parallel, resumable recon pipeline. |
| `analyze -p <program>` | Score hosts Low→Critical and roll signals into attack paths. |
| `playbook [<id>] [--md]` | List the bug-class knowledge base, or render one playbook. |
| `report -p <program> [-f md\|html\|json\|pdf]` | Write an engagement report. |
| `advise -p <program> [--provider] [--yes]` | LLM action plan (local, or cloud with approval). |
| `secrets <paths…> [--endpoints] [--out]` | Scan gathered text for leaked secrets + JS endpoints (redacted). |
| `fingerprint <file\|-> [--out]` | Identify CDN / WAF / cloud / tech from response headers. |
| `config` · `plugins` · `workspace` | Manage config, inspect the tool registry, list workspaces. |
| `clean -p <program>` | Reset stage state and/or clear the tool cache. |

Bug classes: `idor`, `bac`, `xss`, `ssrf`, `sqli`, `ssti`, `subtakeover`,
`authn`, `cors`.

---

## How it fits together

```
recon  ──▶  intel.analyze  ──▶  report  ──▶  advise
(tools)     (signals→score     (md/html/json)  (LLM, gated)
             →attack paths)          │
                   └──────▶ knowledge playbooks (huntkit playbook <id>)

secrets / fingerprint — standalone scanners over content you've gathered
```

The recon layer is a thin orchestrator over **plugins**; the analysis,
knowledge, reporting, AI and scanner layers are pure feature packages that build
on a small `core` (config, workspace, state, runner) and `utils`.

---

## Security model

- **Scope guard** — recon refuses any host not matched by the program's in-scope
  list (and honours out-of-scope patterns).
- **Safe subprocess** — tools are run argv-only, never through a shell.
- **Redaction** — the secret scanner masks every match, so its tables and JSON
  locate a leak without re-leaking it.
- **Cloud-AI approval gate** — a local provider (Ollama) stays offline. A cloud
  provider is sent nothing unless you confirm, after being shown the exact text
  and the destination host — and that check is enforced in the advisor layer,
  not just the CLI.
- **Engagement data is gitignored** — never commit a workspace.

---

## Extending — add a row, not a branch

The framework is built around declarative catalogs:

| To add… | Drop a row in… |
| --- | --- |
| an external tool | a one-file plugin in `huntkit/plugins/` |
| a scoring heuristic | `PORT_RULES` / `PATH_RULES` / … in `huntkit/intel/signals.py` |
| a bug-class playbook | `PLAYBOOKS` in `huntkit/knowledge/playbooks.py` |
| a secret pattern | `SECRET_PATTERNS` in `huntkit/secrets/patterns.py` |
| a CDN/WAF/tech fingerprint | `FINGERPRINT_RULES` in `huntkit/fingerprint/rules.py` |

---

## Workspace layout

```
~/.huntkit/<program>/
├── scope/     in/out scope lists
├── recon/     subdomains.txt, resolved.txt, live.txt, ports.txt
├── urls/      urls.txt
├── scans/     intel.json, secrets.json, nuclei output …
├── notes/     your own notes
├── reports/   generated md / html / json
└── state.json stage tracking + counts
```

Override the base dir with `-w <dir>` or `$HUNTKIT_HOME`.

---

## Development

```bash
pip install -e ".[dev]"
ruff check huntkit tests     # lint
mypy huntkit                 # type-check
pytest --cov=huntkit         # tests (93% coverage, gate at 90%)
```

CI runs all three on Python 3.10–3.13.

---

## Acknowledgements

HuntKit's AI advisor (`feat(ai): multi-provider advisor with cloud-approval gate`)
was selected for the [XERJ Corpus Hub](https://hub.xerj.org) as a reference
implementation, under this repository's MIT license with attribution.

---

## License

MIT — see [LICENSE](LICENSE).
