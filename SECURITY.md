# Security Policy

HuntKit is a security tool, so we hold its own code to the standard it helps
others enforce. If you find a vulnerability in HuntKit itself, thank you — please
report it responsibly.

## Supported versions

Security fixes land on the latest released minor version. Older versions are not
patched; upgrade to the current release.

| Version | Supported |
| ------- | --------- |
| 0.4.x   | ✅        |
| < 0.4   | ❌        |

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/Raresney/HuntKit/security/advisories/new).
2. Open a new draft advisory describing the issue.

Please include:

- the affected version or commit,
- a clear description of the vulnerability and its impact,
- steps to reproduce (a minimal proof of concept helps a lot),
- any suggested remediation if you have one.

### What to expect

- An acknowledgement within a few days.
- An honest assessment of severity and a fix timeline.
- Credit in the release notes when the fix ships, unless you'd rather stay
  anonymous.

## Scope

In scope: issues in HuntKit's own code — for example command injection through
its orchestration layer, scope-guard bypasses that let recon reach out-of-scope
hosts, unsafe handling of tool output, or secrets leaking into reports.

Out of scope: vulnerabilities in the third-party recon tools HuntKit drives
(report those to their maintainers), and any finding that requires the operator
to deliberately point HuntKit at a target they aren't authorised to test.

## Responsible use

HuntKit enforces a per-program scope list and is built for authorised testing
only. Reports about using HuntKit to attack systems you don't own or have
permission to test are not security vulnerabilities — they're misuse, and
they're on the operator.
