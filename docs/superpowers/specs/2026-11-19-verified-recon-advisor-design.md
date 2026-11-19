# Design: verified surface and a grounded testing plan

## Intent and why

HuntKit today aggregates other people's recon tools and scores the result by the
shape of the surface. The signal engine matches URL paths, query parameters,
ports, and subdomain labels against static rule tables. A URL that carried
`/.svn/` in a wayback crawl becomes a high finding even if that path now returns
404. The code says this plainly: the recon matchers "score potential from the
shape of the surface," and only the active scanner produces "confirmed" hits.

The AI advisor has the same ceiling. It receives a summary (host, score, the
names of the bug-class playbooks, the signal titles) and nothing else. The model
never sees the real request, the response, the tech stack, or the parameter
values. So its advice stays generic. A hunter gets a better answer by pasting the
actual request and response into Claude by hand, which is exactly what our target
user does today.

This design changes what HuntKit produces. Instead of a ranked list of maybe-live
guesses plus generic advice, it produces a verified surface and a specific,
grounded testing plan that a hunter can act on or import into their own tools.

The target user is a web bug-bounty hunter who works in Burp Suite and uses an LLM
for ideas. The recon-aggregation space is crowded; turning recon into trustworthy,
actionable next steps is not. That gap is the whole point.

## Goals

- Confirm whether a signal is actually live before it reaches the operator, with
  evidence attached (status, matched signature, response size).
- Separate confirmed findings from unconfirmed leads everywhere HuntKit reports:
  the terminal, the markdown and JSON reports, and the SARIF.
- Feed the advisor real per-endpoint evidence, so its testing ideas are specific
  to the target and come with a concrete request to try.
- Let a hunter take the plan into their workflow: ready-to-run curl commands and a
  Burp-importable target set.
- Keep the existing guarantees intact: the scope guard, the pacing and politeness
  controls, and the cloud-approval gate on anything that leaves the machine.

## Non-goals

- Automatic exploitation. HuntKit confirms that a path is live and that a
  parameter reaches a sink; it does not fire injection payloads or try to prove
  impact. That stays the operator's manual step, in Burp.
- Replacing nuclei or dalfox. The active scan phase stays as it is. Verification
  is a lighter, targeted check of the recon signals, not a vulnerability scanner.
- A hosted service, a queue, or any always-on component. HuntKit stays local and
  CLI-first.

## Anti-goals

Things that would make this a failure even if it shipped and ran:

- Verification that produces its own false positives by mishandling soft-404s or
  catch-all 200 responses. A wrong "confirmed" is worse than an honest "unverified".
- An advisor that invents endpoints, parameters, or responses that were not in the
  evidence. Grounding is the feature; a confident hallucination defeats it.
- Sending more engagement data to a cloud model than the operator can see and
  approve. The richer context must stay inside the same gate, fully previewed.
- Export formats that look impressive but do not actually load into Burp or run as
  written.

## Constraints

- Verification touches the target over HTTP, so it is an authorised-testing action
  and must run behind the scope guard, same as recon and scan. It is a separate,
  explicit phase, so the claim that recon never touches the target stays true.
- Reuse the existing HTTP path (`huntkit/utils/process.py` style execution, or the
  stdlib client already used in enrich and notify, both scheme-guarded to http(s)).
  No new network dependency.
- Reuse the existing pacing, concurrency, and politeness settings. Verification is
  bounded: one or a few probes per signal, with the configured rate limit.
- Keep the "add a row, not a branch" design. A verifier is data attached to a rule,
  not a new code branch per finding type.
- Keep coverage at or above the current 90% gate, and keep ruff, mypy, bandit, and
  pip-audit green.

## Approaches considered

Three ways to raise HuntKit from a fast aggregator to a tool a real hunter prefers.

### A: verify the signals

Add an active pass that confirms each recon signal with a bounded HTTP probe, and
give every signal a state (confirmed, dead, unverified) with evidence. Only
confirmed signals get promoted; dead ones drop out of the high band. This attacks
the false-positive weakness head on and makes the output trustworthy. On its own it
is defensive polish. It does not serve the Burp-and-LLM workflow directly.

### B: ground the advisor in evidence

Capture a real per-endpoint fingerprint (status, tech, headers, title, size, a
response snippet, reflected-parameter markers) and feed the advisor per-target
blocks instead of a thin summary. The model returns specific, testable checks with
the exact request to try. This is the manual Claude workflow, automated and
grounded. It depends on the quality of the evidence and of the model, and it sends
more data through the cloud gate.

### C: bridge to Burp

Export the scored, verified surface and the testing plan as artifacts the hunter
imports: a target scope, a URL set, and ready-to-run requests. Pure workflow
integration. On its own, without B's sharper ideas, it is a nicer import of the
same generic list.

### Decision

Build B on top of A, and stage C as the delivery layer once A and B exist. The
chain is the product: recon, then a verified surface (A), then a specific grounded
plan (B), then that plan exported into the hunter's tools (C). A makes B
trustworthy, because the ideas target confirmed surface rather than dead 404s. B is
the differentiator and the user's own workflow. C is how the plan leaves HuntKit.

The user picked this chain and asked that C be included when its turn comes, so the
work is sequenced A, then B, then C, each a self-contained milestone.

## The shape of the build

Three milestones. Each ships on its own, with tests, and leaves HuntKit working.

### Milestone A: verification

A new verification phase runs after recon (and after scan, when scan ran). It runs
by default in the pipeline and in the GitHub Action, with a flag to turn it off
(`--no-verify` on the CLI, an input on the Action). It stays an authorised action
behind the scope guard, so recon itself still never touches the target. For each
path, parameter, and finding signal, it issues a bounded probe and records a result.

- A verifier is a small data object attached to a `Rule`: a request spec (the path
  to fetch, relative to the host, and the method) and a predicate over the response
  (status set, a body signature, a content-type check). Rules without a verifier
  stay unverified, which is honest rather than wrong.
- Examples: `git-exposed` fetches `/.git/HEAD` and expects a body that begins
  `ref: `. `svn-exposed` fetches a known SVN metadata file and expects its
  signature. `env-exposed` fetches `/.env` and expects key=value lines and a
  non-HTML content-type. `admin-panel` fetches the path and expects a login or an
  auth challenge (200 with a form, 401, or 403), not a 404 or a soft-404.
- Soft-404 handling: before probing a host, request a random unlikely path and
  record what a "miss" looks like (status, size, a hash of the body). A probe that
  matches the miss baseline is treated as dead, not confirmed.
- Each `Signal` gains a verification state and evidence. Scoring promotes confirmed
  signals and demotes dead ones. The reports and the SARIF distinguish the three
  states: confirmed keeps its level, unverified is marked as a lead, dead is
  suppressed or dropped to informational.
- The phase respects the scope guard, the rate limit, and concurrency, and never
  sends a non-http(s) request.

### Milestone B: grounded advisor

Capture and store a per-endpoint fingerprint during recon and verification, then
rebuild the advisor context around it.

- Evidence per endpoint: final URL and method, status, server and tech headers,
  page title, content-type, size, a short response snippet, the observed
  parameters with a sample value each, whether a parameter value is reflected, and
  the verification state.
- The advisor context changes from a host summary to per-target evidence blocks for
  the top-ranked confirmed endpoints. The system prompt asks for concrete, testable
  checks per endpoint, each with the exact request to run, mapped to the bug class.
- The output is a structured plan: per endpoint, a ranked set of hypotheses, each
  with a concrete probe request and a one-line reason. The plan is what later feeds
  the export.
- The cloud-approval gate still wraps the send. The expanded context goes to cloud
  providers too, not only local ones, so the approval preview shows the full
  evidence that would leave the machine before anything is sent. The local-provider
  path is unchanged and sends nothing off the host.
- Guardrails: the plan suggests manual checks, never destructive payloads, and the
  report states plainly that the model can be wrong and the hunter verifies.

### Milestone C: export to the hunter's tools

Turn the verified surface and the plan into artifacts.

- curl: one ready-to-run command per hypothesis, with the method, headers, and the
  parameter under test marked.
- Burp, two parts, both in scope for this milestone:
  - Importable files: a target scope and a URL set in a format Burp loads natively,
    plus the plan as a readable checklist.
  - A Burp extension that pulls HuntKit's exported plan into Burp directly: it reads
    the plan, seeds the ranked endpoints into the sitemap and the scope, and
    annotates each with its hypotheses and verification state, so the hunter opens
    Burp and finds the targets already ranked and noted.

The extension is a JVM artifact, not part of the Python package, so it is built and
released on its own and does not touch the zero-runtime-dependency rule for
`huntkit` itself. The builder picks the extension stack (the Montoya API in Java, or
Jython against the same API) and how the plan crosses into it (the exported plan
file is the contract).

## What is left to the builder

- The exact module layout (a new `huntkit/verify/` package versus folding the probe
  into the intel engine), chosen to fit the existing structure.
- The precise verifier request-and-predicate for each rule that gets one, and which
  rules ship with a verifier in the first cut (the high-value ones first).
- The verification-state representation on `Signal` and how scoring weights each
  state, within the existing severity model.
- The evidence record's fields and storage, reusing what httpx already returns where
  possible.
- The structured-plan data model and how it serialises for the export.
- The initial Burp-import format, confirmed against a real Burp import.

## Decisions the operator made

Settled before the plan, so the builder does not guess them:

1. Verification runs by default in the pipeline and the Action, with a flag to turn
   it off. It stays authorised-only, behind the scope guard.
2. The grounded advisor sends the expanded evidence to cloud providers as well as
   local ones, behind the same approval gate, which previews the full context before
   anything leaves the machine.
3. The Burp extension is in scope for milestone C from the start, alongside the
   importable files, not deferred.
