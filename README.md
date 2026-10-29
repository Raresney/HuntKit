# HuntKit

[![CI](https://github.com/Raresney/HuntKit/actions/workflows/ci.yml/badge.svg)](https://github.com/Raresney/HuntKit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-blue)
![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen)
![Release](https://img.shields.io/badge/release-v0.2.0-blue)

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
- **Active scanning** — `scan` drives the vuln/fuzz plugins (nuclei, dalfox, …)
  over the URLs recon gathered, **re-checked against scope**, writing findings
  to the workspace's `scans/` dir — where `analyze` folds them into host scoring.
- **Intelligence engine** — turns recon output **and scan findings** into scored,
  prioritised hosts and **attack paths** (which bug class to run, and where), from
  a declarative signal catalog. Pure and offline — it never touches the target.
- **Knowledge base** — full playbooks for 9 bug classes (detection, payloads,
  bypasses, tools, references), cross-linked from the attack paths.
- **Reporting** — one model rendered to Markdown, a self-contained HTML page, or
  JSON (PDF when `weasyprint` is present, else print-ready HTML).
- **AI advisor (optional)** — hand the scored surface to a local Ollama model, or
  a cloud model (Claude/OpenAI) **only after an explicit approval prompt that
  shows exactly what will be sent**.
- **Content scanners** — a redacting secret & JS-endpoint scanner, and a
  header-based CDN/WAF/cloud/tech fingerprinter.
- **Asset-correlation enrichment** — `enrich` hashes each origin's favicon
  (the Shodan `http.favicon.hash:` pivot) and maps every host to its ASN /
  BGP prefix, turning one asset into the rest of the estate to sweep.
- **Screenshot gallery** — `shots` drives `gowitness` over the live URLs and
  the report embeds the captures as a grid (inlined, so the HTML stays one
  self-contained file) — eyeball a big surface at a glance.
- **Diff across runs** — `diff` snapshots a program's result set and shows the
  delta on the next sweep: new subdomains, freshly-live URLs, and above all
  **new findings** — the thing you actually re-run a program to catch.
- **Live dashboard** — `dashboard` paints the whole engagement on one screen
  (priority, recon surface, top hosts, attack paths, notable exposures,
  enrichment) and `--watch` redraws it live. Built on Rich — no extra deps.
- **Continuous monitoring** — `monitor` re-sweeps a program, diffs the result
  set against the last snapshot, and pings a Slack/Discord webhook the moment a
  **new finding** turns up. `--interval N` loops every N minutes — a program
  watches itself while you sleep.

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

On a Debian-family box (Kali / Ubuntu), the whole toolchain plus HuntKit itself
installs in one shot:

```bash
bash scripts/install-tools.sh    # apt + go install + arjun, then huntkit in a venv
```

The tools are Linux-native — a Kali VM (or WSL) is the intended runtime.

### Docker — the whole toolchain, baked

No Linux box to set up? The image carries HuntKit **and** every external tool,
so it runs anywhere Docker does:

```bash
docker build -t huntkit .
docker run --rm huntkit doctor

# a real run — mount a dir to keep workspaces, add caps for naabu's SYN scan
docker run --rm -v "$PWD/hk-data:/data" \
    --cap-add=NET_ADMIN --cap-add=NET_RAW \
    huntkit recon acme.com -p acme
```

Engagement data lives in the `/data` volume (`HUNTKIT_HOME`); mount a host
directory to keep it between runs. The image never bakes in a workspace.

---

## Quick start

```bash
# 1. create a workspace + declare scope
python -m huntkit init acme -s "*.acme.com" -x blog.acme.com

# 2. run the recon pipeline
python -m huntkit recon acme.com -p acme

# 3. actively scan the gathered URLs (nuclei, dalfox, …)
python -m huntkit scan -p acme

# 4. enrich: favicon hashes (Shodan pivot) + ASN/BGP origins
python -m huntkit enrich -p acme

# 5. screenshot every live URL (feeds the report gallery)
python -m huntkit shots -p acme

# 6. score the surface into prioritised hosts + attack paths
python -m huntkit analyze -p acme

# 7. pull a full playbook for a bug class the analysis points at
python -m huntkit playbook ssrf

# 8. write a shareable report (embeds the screenshot gallery)
python -m huntkit report -p acme -f html

# 9. (optional) ask a local LLM to prioritise it
python -m huntkit advise -p acme --provider ollama

# 10. (optional) re-sweep on a schedule, ping me when a new finding lands
python -m huntkit monitor acme.com -p acme \
    --webhook "$SLACK_WEBHOOK" --interval 360
```

With a single workspace, `-p` is inferred.

---

## Commands

| Command | What it does |
| --- | --- |
| `doctor` | Show which external tools are installed / missing, and where data lives. |
| `init <program> -s <scope>` | Create a workspace and set in/out scope (`*.wildcards` ok). |
| `recon <domain> [--stage] [--threads] [--fresh] [--no-cache]` | Parallel, resumable recon pipeline. |
| `scan -p <program> [--tool] [--threads] [--no-cache]` | Run the vuln/fuzz scanners (nuclei, dalfox) over the gathered in-scope URLs. |
| `enrich -p <program> [--favicon/--no-favicon] [--asn/--no-asn]` | Favicon hashes (Shodan pivot) + ASN/BGP origin per host. |
| `shots -p <program>` | Screenshot every live in-scope URL (gowitness) for the report gallery. |
| `analyze -p <program>` | Score hosts Low→Critical and roll signals into attack paths. |
| `playbook [<id>] [--md]` | List the bug-class knowledge base, or render one playbook. |
| `report -p <program> [-f md\|html\|json\|pdf]` | Write an engagement report. |
| `diff -p <program> [--save] [--against <id>] [--list]` | Snapshot the result set and show what changed since a baseline. |
| `dashboard -p <program> [--watch <secs>]` | One-screen engagement overview; `--watch` redraws it live. |
| `monitor <domain> -p <program> [--webhook <url>] [--notify-on findings\|changes] [--interval <min>]` | Re-sweep, diff vs. last snapshot, and webhook-notify on new findings. |
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
recon  ──▶  scan  ──▶  intel.analyze  ──▶  report  ──▶  advise
(tools)    (nuclei/    (scores recon +     (md/html/json)  (LLM, gated)
            dalfox)     scan findings →          │
                        attack paths)            │
                              └──────▶ knowledge playbooks (huntkit playbook <id>)

enrich — favicon hashes + ASN/BGP origins over the recon surface (pivot outward)
shots  — gowitness screenshots of the live URLs, embedded in the HTML report
secrets / fingerprint — standalone scanners over content you've gathered
diff   — snapshot the result set and show the delta on the next sweep
monitor — re-sweep on a schedule; diff vs. last snapshot; webhook on new findings
```

The recon layer is a thin orchestrator over **plugins**; the analysis,
knowledge, reporting, AI and scanner layers are pure feature packages that build
on a small `core` (config, workspace, state, runner) and `utils`.

---

## Security model

- **Scope guard** — recon refuses any host not matched by the program's in-scope
  list (and honours out-of-scope patterns).
- **Safe subprocess** — tools are run argv-only, never through a shell.
- **Politeness, one knob** — `http.rate_limit` (requests/sec), `http.delay`
  (seconds between requests) and `general.rate` (port-scan packets/sec) are a
  single policy that HuntKit maps onto every rate-aware tool's native flags
  (subfinder, dnsx, httpx, naabu, katana, nuclei, ffuf, dalfox). Dial a program
  down to a gentle crawl in one place — real programs ban noisy scanners.
- **Redaction** — the secret scanner masks every match, so its tables and JSON
  locate a leak without re-leaking it.
- **Cloud-AI approval gate** — a local provider (Ollama) stays offline. A cloud
  provider is sent nothing unless you confirm, after being shown the exact text
  and the destination host — and that check is enforced in the advisor layer,
  not just the CLI.
- **Webhook egress is opt-in** — `monitor` only POSTs to a webhook you pass
  explicitly (`--webhook`), scheme-guarded to http(s). Sending a diff to
  Slack/Discord is egress of engagement data to a third party, so it never
  happens by default and the CLI names the destination host before it sends.
- **Enrichment egress is named** — `enrich` fetches favicons from in-scope
  targets (scheme-guarded to http/https), and its ASN lookup sends a resolved
  in-scope IP to Team Cymru's public WHOIS — the one call to a non-target host,
  called out in the CLI before it runs.
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
├── scans/     intel.json, findings.json, enrich.json, screenshots.json …
├── notes/     your own notes
├── history/   timestamped result snapshots (for `diff`)
├── reports/   generated md / html / json  (+ shots/ screenshots)
└── state.json stage tracking + counts
```

Override the base dir with `-w <dir>` or `$HUNTKIT_HOME`.

---

## Development

```bash
pip install -e ".[dev]"
ruff check huntkit tests     # lint
ruff format huntkit tests    # format (CI checks with --check)
mypy huntkit                 # type-check
pytest --cov=huntkit         # tests (92% coverage, gate at 90%)
```

CI runs lint, format-check, type-check and tests on Python 3.10–3.13.

---

## Acknowledgements

HuntKit's AI advisor (`feat(ai): multi-provider advisor with cloud-approval gate`)
was selected for the [XERJ Corpus Hub](https://hub.xerj.org) as a reference
implementation, under this repository's MIT license with attribution.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Current release: **v0.2.0**.

---

## License

MIT — see [LICENSE](LICENSE).
