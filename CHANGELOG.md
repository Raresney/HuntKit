# Changelog

All notable changes to HuntKit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Community health docs: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
  and GitHub issue / pull-request templates.
- Self-security CI: a `security` job runs `bandit` (static analysis) and
  `pip-audit` (dependency CVE audit) over HuntKit's own code on every push and
  pull request.

### Security

- Hardened the AI provider HTTP path with a scheme guard that refuses any
  non-`http(s)` endpoint before `urllib` opens it, matching the guards already
  on the enrich and webhook fetchers.

## [0.4.0] - 2026-11-16

### Added

- **SARIF export** — `report -f sarif` emits a SARIF 2.1.0 document, so a
  HuntKit sweep feeds straight into GitHub code scanning (the Security tab) or
  any CI security dashboard. Each signal becomes a result located at the
  affected host, with the severity driving both the SARIF level and GitHub's
  `security-severity` score, and a stable fingerprint so a tracker can de-dupe
  the same finding across repeated sweeps. An empty sweep still writes a valid,
  empty document.
- **Reusable GitHub Action** — a composite `action.yml` runs a recon + scan
  sweep in the full-toolchain container image and writes a SARIF report. Pair
  it with `github/codeql-action/upload-sarif` for scheduled recon that lands in
  the Security tab with no glue code; a copy-paste workflow lives in
  `examples/code-scanning.yml`. Inputs cross into the container as environment
  variables rather than being interpolated into the shell.
- **IP / CIDR recon seeds** — `recon <ip|cidr>` seeds the pipeline from an
  address or range, not just a domain. The subdomain phase is skipped and the
  live/ports/urls stages run over the range (the tools expand a CIDR natively).
  A seed must fall inside the authorised scope and may not overlap an excluded
  range; ranges wider than `/16` are warned about.
- **nuclei passthrough** — `scan -N/--nuclei-arg` forwards extra arguments to
  nuclei for one run (e.g. `-N -system-resolvers`), derived onto a config copy
  so the shared config is untouched. A zero-findings diagnostic explains
  nuclei's default `info`-severity exclusion and its own DNS resolver when a
  scan runs over real targets but reports nothing.

### Fixed

- **CIDR scope matching** — a scope entry like `10.0.0.0/8` now matches an IP
  inside it (it was string-compared and silently never matched).
- **`doctor` workspace** — `doctor` reports the effective base, honouring
  `-w/--workspace`, instead of the configured default.
- **urls-stage scope filter** — the `urls` recon stage is now scope-filtered on
  disk, so an excluded host can no longer leak into `urls/urls.txt` or reports.
- **machine-format reports on empty sweeps** — `report -f json|sarif` writes a
  valid, empty file instead of bailing before writing, so a CI pipeline that
  ingests it never breaks on a missing artifact.

## [0.3.0] - 2026-10-29

### Added

- **Demo** — a self-contained terminal-cast SVG (`docs/demo.svg`) embedded in
  the README, showing a full run end to end (scope guard → recon → scan →
  analyze → report → monitor → dashboard). Renders inline on GitHub, no deps.
- **PyPI distribution** — `pip install huntkit`. A tag-triggered release
  workflow builds the sdist + wheel, publishes to PyPI via OIDC trusted
  publishing (no stored token), and cuts a GitHub release.
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
