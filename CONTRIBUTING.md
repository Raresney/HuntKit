# Contributing to HuntKit

Thanks for taking the time to contribute. HuntKit is a local-first recon and
methodology framework for **authorised** security testing, and the same care
that goes into using it responsibly goes into changing it.

## Ground rules

- **Authorised testing only.** Any example, test fixture, or documentation you
  add must target assets that are safe and legal to probe — your own hosts, or
  the public, intentionally vulnerable sandboxes (`scanme.nmap.org`,
  `testphp.vulnweb.com`, and the like). Never commit output, payloads, or
  defaults aimed at systems you don't own or have explicit permission to test.
- **No secrets in commits.** API keys, tokens, cookies, real target data, and
  personal information don't belong in the repo, the tests, or the fixtures.
- Be respectful. See the [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting set up

HuntKit targets Python 3.10+ and has no runtime dependencies beyond Typer, Rich,
and PyYAML. The external recon tools (subfinder, httpx, nuclei, …) are optional
and only needed to run live recon — the test suite doesn't require them.

```bash
git clone https://github.com/Raresney/HuntKit
cd HuntKit
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before you open a PR

CI runs lint, format-check, type-check, and the full test suite on Python 3.10
through 3.13. Run the same checks locally first — they're fast:

```bash
ruff check huntkit tests      # lint
ruff format huntkit tests     # format (CI enforces with --check)
mypy huntkit                  # type-check
pytest --cov=huntkit          # tests + coverage (gate at 90%)
```

All four must be green. New behaviour needs tests; the coverage gate will fail a
PR that drops below 90%.

## Design conventions

HuntKit is built so that most features are **data, not branches**. Before you
reach for a new command or a new `if`, check whether the thing you want is a new
row in a table:

- A new **recon stage** is an entry in the pipeline, not a bespoke function.
- A new **signal / playbook** is a row in the intel tables under `huntkit/data/`.
- A new **report format** is a renderer registered in `huntkit/report/`.

The [Extending](README.md#extending-add-a-row-not-a-branch) section of the
README walks through this. Keeping to it is why the surface stays small.

Other conventions:

- Keep the CLI honest: commands do what their `--help` says, and machine formats
  (`json`, `sarif`) always write a valid document, even on an empty sweep.
- Respect scope. Anything that reaches the network goes through the scope guard.
- Match the surrounding style; `ruff format` owns layout, so don't hand-format.

## Commit and PR hygiene

- One logical change per PR. Small, reviewable diffs merge faster.
- Write a clear title and describe the *why*, not just the *what*.
- Reference the issue you're closing (`Closes #123`).
- Update `CHANGELOG.md` under the `Unreleased` heading when behaviour changes.

## Reporting bugs and requesting features

Use the [issue templates](https://github.com/Raresney/HuntKit/issues/new/choose).
For anything security-sensitive, follow the [Security Policy](SECURITY.md) and
report privately instead of opening a public issue.
