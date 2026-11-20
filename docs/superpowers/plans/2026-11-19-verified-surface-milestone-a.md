# Verified surface (Milestone A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Confirm each recon signal with a bounded HTTP probe, so HuntKit separates confirmed findings from dead or unverified leads everywhere it reports.

**Architecture:** A new `huntkit/verify/` package probes the surface after recon. Each signal rule can carry a verifier (a request path plus a predicate over the response). A verification phase probes every signal that has one, writes the results to `scans/verify.json`, and the pure `analyze()` reads that file and tags each signal with a state. Scoring and the reports then promote confirmed signals and drop dead ones. Verification touches the target, so it runs behind the scope guard as its own phase, and recon itself stays non-touching.

**Tech Stack:** Python 3.10+, standard library only (`urllib` for the probe, same scheme-guarded pattern already used in `huntkit/enrich` and `huntkit/notify`), Typer for the CLI, pytest.

**Spec:** docs/superpowers/specs/2026-11-19-verified-recon-advisor-design.md

## Global Constraints

- Python floor: `requires-python = ">=3.10"`. No new runtime dependency; the probe uses the standard library only.
- Every probe goes through the workspace scope guard (`Workspace.in_scope(host)`); an out-of-scope host is never requested.
- The probe is bounded: a short per-request timeout (default 10 seconds, separate from `general.timeout`), a capped response read (default 65536 bytes), and the configured politeness delay (`http.delay`) between requests. It reuses `http.user_agent`, `http.headers`, and `http.proxy`.
- The probe accepts only `http` and `https` URLs; any other scheme is refused before the request, matching `huntkit/enrich/engine.py` and `huntkit/notify/webhook.py`.
- Coverage stays at or above the 90 percent gate. `ruff check`, `ruff format --check`, `mypy huntkit`, `bandit -r huntkit -c pyproject.toml`, and `pip-audit` stay green.
- Code and comments are plain: no em dashes or en dashes in new source, no filler comments that restate the code, no comment that narrates a diff.
- Commits use the project's established HuntKit author identity (the same name and address every prior commit uses, passed with `git -c user.name=... -c user.email=...`) and carry no Co-Authored-By or generated-by trailer.

## Review Focus

- A catch-all host that returns 200 for any path must not confirm a path signal. Owned by Task 4 (soft-404 baseline test).
- A probe that times out or hits a transport error must leave the signal unverified, never mark it dead. Owned by Task 4 (transport-error test).
- A signal whose host has no live http(s) base URL (for example a port-only signal) must be skipped and stay unverified. Owned by Task 4 (no-base-url test).
- An out-of-scope host that appears in the signal set must never be probed. Owned by Task 4 (scope-guard test).
- A response body larger than the cap must not be fully read into memory. Owned by Task 1 (capped-read test).

---

### Task 1: Bounded probe client

**Files:**
- Create: `huntkit/verify/__init__.py`
- Create: `huntkit/verify/client.py`
- Test: `tests/verify/test_client.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `@dataclass(frozen=True) class Probe: url: str; status: int; body: str; content_type: str; size: int` (status is 0 on a transport error or refused scheme; size is the byte length read).
  - `def probe(url: str, *, timeout: float = 10.0, max_bytes: int = 65536, user_agent: str = "", headers: dict[str, str] | None = None, proxy: str | None = None) -> Probe`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/verify/test_client.py
# Use a local http.server on 127.0.0.1 (a fixture that serves canned responses),
# never a remote host.
def test_probe_returns_status_body_and_content_type(http_server):
    p = probe(http_server.url("/hello"))        # server returns 200, "hi", text/plain
    assert p.status == 200 and p.body == "hi" and p.content_type.startswith("text/plain")

def test_probe_caps_the_body_read(http_server):
    p = probe(http_server.url("/big"), max_bytes=16)   # server returns 1 MB
    assert p.size <= 16 and len(p.body) <= 16

def test_probe_non_http_scheme_is_refused():
    p = probe("file:///etc/passwd")
    assert p.status == 0

def test_probe_transport_error_yields_status_zero():
    p = probe("http://127.0.0.1:1/")            # nothing listening
    assert p.status == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/verify/test_client.py -v`
Expected: FAIL (module `huntkit.verify.client` not found).

- [ ] **Step 3: Implement `probe` and `Probe` in `huntkit/verify/client.py`**

Scheme-guard with `urllib.parse.urlsplit`; build a `urllib.request.Request` with the user agent and headers; open it through a `ProxyHandler` opener when `proxy` is set. Read at most `max_bytes` with a single `resp.read(max_bytes)`. Decode the body with `errors="replace"`. Catch `urllib.error.URLError`, `OSError`, and `ValueError` and return `Probe(url, 0, "", "", 0)`. An `HTTPError` still carries a status, so read its code and body. Add `# nosec B310` on the `urlopen` line with the scheme-guard note on the preceding line.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/verify/test_client.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add huntkit/verify/__init__.py huntkit/verify/client.py tests/verify/test_client.py
git commit -m "feat(verify): bounded, scheme-guarded HTTP probe client"
```

---

### Task 2: Verifier model and registry

**Files:**
- Create: `huntkit/verify/verifiers.py`
- Test: `tests/verify/test_verifiers.py`

**Interfaces:**
- Consumes: `Probe` from Task 1.
- Produces:
  - `@dataclass(frozen=True) class Verifier: path: str; confirm: Callable[[Probe], bool]; method: str = "GET"` (`path` is host-relative, for example `/.git/HEAD`).
  - `VERIFIERS: dict[str, Verifier]` keyed by `Rule.id`. First cut covers: `git-exposed`, `svn-exposed`, `env-exposed`, `phpinfo`, `apache-status`, `spring-actuator`, `phpmyadmin`, `adminer`, `admin-panel`, `internal-path`. Each other rule id is simply absent, which keeps its signals unverified.
  - `def confirms(rule_id: str, probe: Probe) -> bool | None` returns the predicate result, or `None` when the rule has no verifier.

- [ ] **Step 1: Write the failing tests**

```python
# tests/verify/test_verifiers.py
def test_git_exposed_confirms_on_ref_head():
    p = Probe("http://h/.git/HEAD", 200, "ref: refs/heads/main\n", "text/plain", 21)
    assert VERIFIERS["git-exposed"].path == "/.git/HEAD"
    assert VERIFIERS["git-exposed"].confirm(p) is True

def test_git_exposed_rejects_html_404_page():
    p = Probe("http://h/.git/HEAD", 200, "<html>not found</html>", "text/html", 22)
    assert VERIFIERS["git-exposed"].confirm(p) is False

def test_phpinfo_confirms_on_signature():
    p = Probe("http://h/phpinfo", 200, "<title>phpinfo()</title>", "text/html", 24)
    assert VERIFIERS["phpinfo"].confirm(p) is True

def test_admin_panel_confirms_on_auth_status():
    assert VERIFIERS["admin-panel"].confirm(Probe("http://h/admin", 401, "", "", 0)) is True
    assert VERIFIERS["admin-panel"].confirm(Probe("http://h/admin", 404, "", "", 0)) is False

def test_confirms_returns_none_for_unknown_rule():
    assert confirms("reflect-param", Probe("http://h/", 200, "", "", 0)) is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/verify/test_verifiers.py -v`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement the verifiers in `huntkit/verify/verifiers.py`**

Each predicate checks the probe the way the spec describes: `git-exposed` needs `status == 200` and a body that starts with `ref: ` and a non-HTML content type; `svn-exposed` needs the SVN metadata signature; `env-exposed` needs `status == 200`, a non-HTML content type, and a `KEY=value` line; `phpinfo` needs the `phpinfo()` title; `apache-status` needs the `Apache Server Status` heading; `spring-actuator` needs a JSON content type with an actuator key; the panel rules (`phpmyadmin`, `adminer`, `admin-panel`, `internal-path`) confirm on an auth-bearing status (200 with a form or login marker, 401, or 403) and reject 404. Implement `confirms` as a dict lookup that returns `None` when absent.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/verify/test_verifiers.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add huntkit/verify/verifiers.py tests/verify/test_verifiers.py
git commit -m "feat(verify): per-rule verifier registry with response predicates"
```

---

### Task 3: Signal verification state

**Files:**
- Modify: `huntkit/intel/signals.py` (the `Signal` dataclass and `to_dict`, near lines 35-58)
- Test: `tests/test_signals.py` (add cases; create if the suite keeps signal tests elsewhere, matching the existing layout)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `class VerifyState(IntEnum): UNVERIFIED = 0; CONFIRMED = 1; DEAD = 2`, with a `label` property returning `"unverified" | "confirmed" | "dead"`.
  - `Signal` gains two fields with defaults so every existing constructor keeps working: `state: VerifyState = VerifyState.UNVERIFIED` and `verified_evidence: str = ""`.
  - `Signal.to_dict()` includes `"state": self.state.label` and, when non-empty, `"verified_evidence"`.

- [ ] **Step 1: Write the failing tests**

```python
def test_signal_defaults_to_unverified():
    s = Signal("git-exposed", "t", Severity.HIGH, "path", "h", "e")
    assert s.state is VerifyState.UNVERIFIED and s.to_dict()["state"] == "unverified"

def test_signal_carries_verified_state_and_evidence():
    s = Signal("git-exposed", "t", Severity.HIGH, "path", "h", "e",
               state=VerifyState.CONFIRMED, verified_evidence="200 ref: refs/")
    d = s.to_dict()
    assert d["state"] == "confirmed" and d["verified_evidence"] == "200 ref: refs/"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_signals.py -k verif -v`
Expected: FAIL (`VerifyState` not defined / unexpected keyword).

- [ ] **Step 3: Add `VerifyState` and the two fields in `huntkit/intel/signals.py`**

Keep `Signal` frozen; the new fields are keyword-friendly because they have defaults and sit after the existing ones.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_signals.py -k verif -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add huntkit/intel/signals.py tests/test_signals.py
git commit -m "feat(intel): add a verification state to Signal"
```

---

### Task 4: Verification engine

**Files:**
- Create: `huntkit/verify/engine.py`
- Test: `tests/verify/test_engine.py`

**Interfaces:**
- Consumes: `probe` and `Probe` (Task 1), `confirms` and `VERIFIERS` (Task 2), `Signal` and `VerifyState` (Task 3).
- Produces:
  - `@dataclass(frozen=True) class VerifyResult: state: VerifyState; evidence: str`.
  - `def base_for_host(live_urls: list[str]) -> dict[str, str]` maps a host to one base origin (`scheme://host`), preferring an https URL over http.
  - `def verify_signals(signals: list[Signal], *, bases: dict[str, str], in_scope: Callable[[str], bool], probe_fn=probe, delay: float = 0.0) -> dict[tuple[str, str], VerifyResult]`. Keys are `(host, rule_id)`. It baselines each host once against a random unlikely path, then probes each signal whose rule has a verifier, applying the predicate and the soft-404 guard. Hosts that are out of scope or have no base are skipped and produce no result.
  - `def apply_results(signals: list[Signal], results: dict[tuple[str, str], VerifyResult]) -> list[Signal]` returns new signals with `state` and `verified_evidence` set via `dataclasses.replace`; a signal with no result is returned unchanged.

- [ ] **Step 1: Write the failing tests**

```python
# A fake probe_fn maps url -> Probe so the engine is tested without a network.
def test_confirmed_when_predicate_matches():
    sig = Signal("git-exposed", "t", Severity.HIGH, "path", "h", "e")
    fake = {"http://h/.git/HEAD": Probe("", 200, "ref: refs/heads/main", "text/plain", 20),
            MISS: Probe("", 404, "", "", 0)}  # baseline miss
    out = verify_signals([sig], bases={"h": "http://h"}, in_scope=lambda h: True,
                         probe_fn=lambda u, **k: fake.get(u, fake[MISS]))
    assert out[("h", "git-exposed")].state is VerifyState.CONFIRMED

def test_catch_all_200_host_is_not_confirmed():
    # every path including the baseline returns the same 200 body -> dead, not confirmed
    sig = Signal("admin-panel", "t", Severity.MEDIUM, "path", "h", "e")
    out = verify_signals([sig], bases={"h": "http://h"}, in_scope=lambda h: True,
                         probe_fn=lambda u, **k: Probe(u, 200, "same page", "text/html", 9))
    assert out[("h", "admin-panel")].state is VerifyState.DEAD

def test_transport_error_stays_unverified():
    sig = Signal("git-exposed", "t", Severity.HIGH, "path", "h", "e")
    out = verify_signals([sig], bases={"h": "http://h"}, in_scope=lambda h: True,
                         probe_fn=lambda u, **k: Probe(u, 0, "", "", 0))
    assert out[("h", "git-exposed")].state is VerifyState.UNVERIFIED

def test_signal_without_base_is_skipped():
    sig = Signal("git-exposed", "t", Severity.HIGH, "path", "h", "e")
    out = verify_signals([sig], bases={}, in_scope=lambda h: True, probe_fn=_unused)
    assert ("h", "git-exposed") not in out

def test_out_of_scope_host_is_never_probed():
    calls = []
    def spy(u, **k): calls.append(u); return Probe(u, 200, "", "", 0)
    sig = Signal("git-exposed", "t", Severity.HIGH, "path", "h", "e")
    verify_signals([sig], bases={"h": "http://h"}, in_scope=lambda h: False, probe_fn=spy)
    assert calls == []

def test_apply_results_sets_state():
    sig = Signal("git-exposed", "t", Severity.HIGH, "path", "h", "e")
    res = {("h", "git-exposed"): VerifyResult(VerifyState.CONFIRMED, "200 ref")}
    assert apply_results([sig], res)[0].state is VerifyState.CONFIRMED
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/verify/test_engine.py -v`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement the engine in `huntkit/verify/engine.py`**

For each host with a base and in scope, probe a random path (for example `/<16 hex chars>`) once to record the miss baseline (status, size, a hash of the body). For each signal on that host whose rule has a verifier, probe `base + verifier.path`; if the probe status is 0, record `UNVERIFIED`; if the probe looks like the baseline miss (same status and body hash, or both are soft-404-ish), record `DEAD`; else record `CONFIRMED` when `confirms(rule_id, probe)` is true and `DEAD` when it is false. Sleep `delay` between probes when `delay > 0`. Evidence is a short string such as `f"{probe.status} {probe.body[:80]}"`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/verify/test_engine.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add huntkit/verify/engine.py tests/verify/test_engine.py
git commit -m "feat(verify): verification engine with soft-404 baseline and scope guard"
```

---

### Task 5: Persist results and apply state in analyze

**Files:**
- Create: `huntkit/verify/store.py`
- Modify: `huntkit/intel/engine.py` (`analyze`, `_priority`, `HostIntel.score`, `IntelReport.attack_paths`)
- Test: `tests/verify/test_store.py`, `tests/test_intel.py` (add cases alongside the existing intel tests)

**Interfaces:**
- Consumes: `VerifyResult`, `VerifyState`, `apply_results` (Task 4); `Workspace`.
- Produces:
  - `def save_results(ws: Workspace, results: dict[tuple[str, str], VerifyResult]) -> Path` writes `scans/verify.json` as `{"results": {"host|rule_id": {"state": "...", "evidence": "..."}}}`.
  - `def load_results(ws: Workspace) -> dict[tuple[str, str], VerifyResult]` reads it back, returning `{}` when the file is missing or malformed (same tolerance as `_read_findings`).
  - `analyze(ws)` now applies loaded results to the signals before grouping. Scoring ignores `DEAD` signals: `_priority` and `HostIntel.score` count only non-dead signals, and `attack_paths` skips dead signals. A host left with only dead signals still appears but scores Low.

- [ ] **Step 1: Write the failing tests**

```python
def test_store_round_trips_results(tmp_path):
    ws = Workspace.open("p", base=tmp_path)
    res = {("h", "git-exposed"): VerifyResult(VerifyState.CONFIRMED, "200 ref")}
    save_results(ws, res)
    assert load_results(ws) == res

def test_load_results_tolerates_missing_file(tmp_path):
    assert load_results(Workspace.open("p", base=tmp_path)) == {}

def test_dead_signal_does_not_raise_priority(tmp_path):
    # a workspace whose only path signal is a high git-exposed, marked DEAD,
    # scores Low, not High
    ...  # seed recon files + verify.json, then analyze(ws)
    assert report.hosts[0].priority is Priority.LOW

def test_confirmed_signal_keeps_its_weight(tmp_path):
    ...  # same signal marked CONFIRMED stays High
    assert report.hosts[0].priority is Priority.HIGH
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/verify/test_store.py tests/test_intel.py -k "dead or confirmed or round_trips or missing" -v`
Expected: FAIL.

- [ ] **Step 3: Implement the store and wire it into `analyze`**

In `store.py`, serialise with the `"host|rule_id"` string key and parse it back to a tuple. In `analyze`, after `scan_signals(...)`, call `apply_results(signals, load_results(ws))`. Change `_priority` and `HostIntel.score` to consider only `s for s in signals if s.state is not VerifyState.DEAD`, and have `attack_paths` skip dead signals. Keep dead signals in `HostIntel.signals` so the report can list them as ruled out.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/verify/test_store.py tests/test_intel.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add huntkit/verify/store.py huntkit/intel/engine.py tests/verify/test_store.py tests/test_intel.py
git commit -m "feat(intel): read verification results and discount dead signals"
```

---

### Task 6: Show verification state in the reports and SARIF

**Files:**
- Modify: `huntkit/report/render.py` (markdown table and the SARIF renderer `to_sarif`, `_sarif_result`)
- Test: `tests/test_report.py` (extend the existing `TestSarif` class and the markdown cases)

**Interfaces:**
- Consumes: `Signal.state`, `VerifyState`.
- Produces:
  - The markdown "Notable exposures" table gains a "state" column showing `confirmed`, `lead` (for unverified), or `ruled out` (for dead).
  - `to_sarif`: a `DEAD` signal is not emitted. A `CONFIRMED` signal keeps its mapped level. An `UNVERIFIED` signal keeps its level but gets `properties.verificationState = "unverified"`; a `CONFIRMED` one gets `"confirmed"`.

- [ ] **Step 1: Write the failing tests**

```python
def test_sarif_omits_dead_signals():
    report = _report_with(states={"git-exposed": VerifyState.DEAD})
    doc = json.loads(to_sarif(report))
    assert all(r["ruleId"] != "git-exposed" for r in doc["runs"][0]["results"])

def test_sarif_marks_verification_state():
    report = _report_with(states={"git-exposed": VerifyState.CONFIRMED})
    r = _result_for(json.loads(to_sarif(report)), "git-exposed")
    assert r["properties"]["verificationState"] == "confirmed"

def test_markdown_shows_confirmed_state():
    assert "confirmed" in to_md(_report_with(states={"git-exposed": VerifyState.CONFIRMED}))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_report.py -k "verif or dead or state" -v`
Expected: FAIL.

- [ ] **Step 3: Implement the report changes in `huntkit/report/render.py`**

Skip dead signals when building SARIF results. Add `verificationState` to the result `properties`. Add the state column to the markdown exposures table, mapping the three states to `confirmed` / `lead` / `ruled out`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_report.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add huntkit/report/render.py tests/test_report.py
git commit -m "feat(report): surface verification state in markdown and SARIF"
```

---

### Task 7: The `verify` command and default pipeline wiring

**Files:**
- Modify: `huntkit/app/main.py` (add a `verify` command; run verification by default after recon with a `--no-verify` opt-out)
- Create: `huntkit/verify/run.py` (a thin orchestrator so the CLI and the pipeline share one entry point)
- Test: `tests/test_cli.py` (add a `verify` case and a `--no-verify` case, using a fake probe)

**Interfaces:**
- Consumes: `verify_signals`, `base_for_host` (Task 4), `save_results` (Task 5), `scan_signals` and the recon readers used by `analyze`, `Workspace`, `Config`.
- Produces:
  - `def run_verify(ws: Workspace, config: Config, *, probe_fn=probe) -> int` builds the candidate signals from the workspace recon files, calls `verify_signals` with `bases` from `base_for_host(live)`, `in_scope=ws.in_scope`, and `delay=config.http.delay`, saves the results, and returns the count of signals probed.
  - A Typer `verify` command (`huntkit verify -p <program>`), and a `--no-verify` flag on the recon pipeline command that otherwise calls `run_verify` after recon finishes.

- [ ] **Step 1: Write the failing tests**

```python
def test_verify_command_writes_results(tmp_path, monkeypatch):
    # seed a workspace with a live url and a git-exposed path url, fake the probe
    result = runner.invoke(app, ["verify", "-p", "demo"])
    assert result.exit_code == 0 and (ws.path("scans", "verify.json")).exists()

def test_recon_runs_verify_by_default(monkeypatch):
    # spy on run_verify; invoking recon without --no-verify calls it once
    assert spy.calls == 1

def test_no_verify_flag_skips_verification(monkeypatch):
    # invoking recon with --no-verify does not call run_verify
    assert spy.calls == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_cli.py -k verify -v`
Expected: FAIL.

- [ ] **Step 3: Implement `run_verify` and the CLI wiring**

Keep `run_verify` in `huntkit/verify/run.py` so the command and the pipeline share it. Build candidate signals with the same `scan_signals` inputs `analyze` uses (live, urls, ports, hosts). Default the recon command to run `run_verify` after recon; `--no-verify` skips it. The standalone `verify` command probes an existing workspace.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add huntkit/app/main.py huntkit/verify/run.py tests/test_cli.py
git commit -m "feat(cli): verify command and default post-recon verification"
```

---

### Task 8: Expose verification in the Action and document it

**Files:**
- Modify: `action.yml` (add a `verify` input, default `"true"`; run the verify step in the container unless disabled)
- Modify: `README.md` (one line in the pipeline and the Action section), `CHANGELOG.md` (an Unreleased entry)
- Test: none (declarative YAML and docs); verified by the YAML parse check already used in CI

**Interfaces:**
- Consumes: the `huntkit verify` command (Task 7).
- Produces: a documented `verify` input on the Action.

- [ ] **Step 1: Add the `verify` input and container step in `action.yml`**

Add `verify` to `inputs` (default `"true"`), pass it as `-e HK_VERIFY`, and in the container script run `huntkit verify -p "$HK_PROGRAM"` between recon and report when `HK_VERIFY` is `true`. Keep the `chmod a+r` fix on the SARIF.

- [ ] **Step 2: Verify the YAML parses**

Run: `python -c "import yaml; yaml.safe_load(open('action.yml', encoding='utf-8')); print('ok')"`
Expected: prints `ok`.

- [ ] **Step 3: Update `README.md` and `CHANGELOG.md`**

One line in the pipeline diagram and the Action input list; an Unreleased changelog entry describing active verification and the three signal states.

- [ ] **Step 4: Run the full suite and the quality gates**

Run: `pytest --cov=huntkit --cov-fail-under=90 && ruff check huntkit tests && ruff format --check huntkit tests && mypy huntkit && bandit -r huntkit -c pyproject.toml`
Expected: all pass, coverage at or above 90 percent.

- [ ] **Step 5: Commit**

```bash
git add action.yml README.md CHANGELOG.md
git commit -m "feat(action): add a verify input and document active verification"
```
