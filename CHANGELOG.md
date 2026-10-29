# Changelog

All notable changes to HuntKit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Docker image** — a multi-stage `Dockerfile` bakes the full external
  toolchain (the ProjectDiscovery Go stack, gowitness + chromium, nmap,
  whatweb, amass, findomain, arjun) plus HuntKit into one image, so it runs on
  any host with Docker. Engagement data lives in the `/data` volume.
- **Continuous monitoring** (`monitor`) — re-sweep a program, diff the result
  set against the last snapshot, and push the delta to a Slack/Discord webhook
  when a new finding (or, with `--notify-on changes`, any new asset) appears.
  `--interval N` loops every N minutes. The webhook POST is opt-in egress and
  scheme-guarded to http(s).
- **Unified rate limiting / politeness** — a single policy (`http.rate_limit`,
  new `http.delay`, `general.rate` for port scanning) is mapped onto every
  rate-aware tool's native flags via `huntkit/core/pacing.py`, so a program can
  be dialed down to a gentle crawl from one place. Previously only httpx,
  nuclei and naabu honoured a rate; now subfinder, dnsx, katana, ffuf and
  dalfox do too, and inter-request delay is new.

### Changed

- Rate flags that were hand-rolled per plugin now come from the shared
  `Pace` policy, keeping the mapping in one tested place.

## [0.2.0] - 2026-10-27

First tagged release. HuntKit 0.2 is a ground-up, modular rewrite of the
unreleased 0.1 single-file prototype: the flat modules are gone, every
capability is its own small package on a shared `core`, and external tools are
one-file plugins the pipeline wires in by capability.

### Added

- **Recon pipeline** — parallel, resumable `subdomains → resolve → live →
  ports → urls`, running every available tool per wave concurrently, deduped
  on disk, with stage resume and an opt-in content-addressed cache.
- **Pluggable toolchain** — each external tool (subfinder, httpx, naabu, gau,
  nuclei, ffuf, dalfox, …) is one file in `huntkit/plugins/`; the registry
  auto-discovers it and the pipeline schedules it by capability.
- **Active scanning** (`scan`) — drives the vuln/fuzz plugins (nuclei, dalfox)
  over the gathered URLs, re-checked against scope, writing findings the
  intelligence engine folds into host scoring.
- **Intelligence engine** (`analyze`) — scores hosts Low→Critical and rolls
  signals into ranked attack paths from a declarative catalog; pure and
  offline. Scan findings are folded into the scoring.
- **Knowledge base** (`playbook`) — full playbooks for 9 bug classes
  (detection, payloads, bypasses, tools, references), cross-linked from the
  attack paths.
- **Reporting** (`report`) — one model rendered to Markdown, a self-contained
  HTML page, or JSON (PDF when `weasyprint` is present, else print-ready HTML).
- **AI advisor** (`advise`) — hand the scored surface to a local Ollama model,
  or a cloud model only after an explicit approval prompt that shows exactly
  what will be sent; the gate is enforced in the advisor layer, not just the
  CLI.
- **Content scanners** — a redacting secret & JS-endpoint scanner (`secrets`)
  and a header-based CDN/WAF/cloud/tech fingerprinter (`fingerprint`).
- **Enrichment** (`enrich`) — favicon hashing (the Shodan `http.favicon.hash:`
  pivot, via a pure-Python MurmurHash3 port — no compiled dependency) and
  per-host ASN / BGP-prefix lookup via Team Cymru.
- **Screenshots** (`shots`) — drives `gowitness` over the live URLs; the report
  embeds the captures as a gallery, inlined so the HTML stays one file.
- **Diff across runs** (`diff`) — snapshots a program's result set and reports
  the delta on the next sweep: new subdomains, freshly-live URLs, and new
  findings.
- **Dashboard** (`dashboard`) — a one-screen engagement overview on Rich, with
  a `--watch` live-refresh mode.
- **Quality gate** — ruff lint, ruff format, mypy, and a pytest suite (297
  tests, ~92% coverage, gate at 90%) running on CI across Python 3.10–3.13.

### Security

- **Scope guard** — recon refuses any host not matched by the program's
  in-scope list and honours out-of-scope patterns; active phases (`scan`,
  `shots`, `enrich`) re-check targets against scope as defence in depth.
- **Safe subprocess** — external tools are run argv-only, never through a
  shell.
- **Redaction** — the secret scanner masks every match in its tables and JSON.
- **Cloud-AI approval gate** — a local provider stays offline; a cloud provider
  is sent nothing without an explicit, destination-showing confirmation.
- **Named egress** — the one enrichment call to a non-target host (Team Cymru
  WHOIS, carrying a resolved in-scope IP) is called out in the CLI before it
  runs; the favicon fetcher is scheme-guarded to http(s).

### Notes

- Runtime dependencies are intentionally light: `typer`, `rich`, `pyyaml`.
- External tools are optional — `doctor` reports what is installed; any missing
  tool simply skips its stage, so HuntKit is useful on a fresh box.

[0.2.0]: https://github.com/Raresney/HuntKit/releases/tag/v0.2.0
