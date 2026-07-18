# HuntKit — Demo walkthrough

A full end-to-end run against [`testphp.vulnweb.com`](http://testphp.vulnweb.com/)
— Acunetix's **public, intentionally vulnerable** test site, provided
specifically for exercising security tooling.

> The recon output below was seeded to keep the demo reproducible offline.
> On Kali with the toolchain installed, `huntkit recon testphp.vulnweb.com`
> produces the same files itself — every command and its output is otherwise
> identical.

---

## 1. Create a workspace and set scope

```console
$ huntkit init vulnweb -d testphp.vulnweb.com -d "*.vulnweb.com"
✓ workspace ready: ~/.huntkit/vulnweb
› in-scope: testphp.vulnweb.com, *.vulnweb.com
› next:  huntkit recon testphp.vulnweb.com -p vulnweb
```

## 2. Scope guard — out-of-scope targets are refused

HuntKit will not run recon against a host you haven't declared in scope:

```console
$ huntkit recon google.com -p vulnweb
✗ google.com is not in scope for 'vulnweb'. Add it:  huntkit init vulnweb -d google.com
# exit code 2 — blocked
```

## 3. Run recon

```console
$ huntkit recon testphp.vulnweb.com -p vulnweb
╭──────────────────────────────────────╮
│ HuntKit recon — testphp.vulnweb.com  │
╰──────────────────────────────────────╯
» Subdomain enumeration  → recon/subdomains.txt
» Probing live hosts     → recon/live.txt, recon/httpx.txt
» Port scanning          → recon/ports.txt
» Gathering known URLs   → urls/all_urls.txt, urls/params.txt
✓ recon complete — see `huntkit status` and `huntkit ideas`
```

## 4. Status

```console
$ huntkit status -p vulnweb
╭──────────────────────────╮
│ HuntKit status — vulnweb │
╰──────────────────────────╯
          Counts
┏━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ metric          ┃ count ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ subdomains      │ 3     │
│ live            │ 2     │
│ urls            │ 9     │
│ nuclei_findings │ 3     │
└─────────────────┴───────┘
```

## 5. Ideas — the context-aware engine

This is the differentiator. `ideas` reads the recon output and cross-references
detected technology, URL patterns, open ports, and nuclei findings to tell you
**where to dig**:

```console
$ huntkit ideas -p vulnweb
╭─────────────────────────╮
│ HuntKit ideas — vulnweb │
╰─────────────────────────╯
» Based on detected technology
  • nginx: alias traversal, misrouted proxy_pass, off-by-slash.
  • PHP: classic injection surface — probe params for SQLi/LFI.
  • Swagger/OpenAPI exposed: map every endpoint, test authz on each.
» Based on gathered URLs
  • Object-id params -> test IDOR / BOLA.  (2 URL(s))
  • File/template params -> test LFI/path traversal & SSTI.  (1 URL(s))
  • Privileged/API paths -> test broken access control.  (1 URL(s))
  • Sensitive file extensions in URLs -> check for exposed backups/secrets.  (1 URL(s))
» Based on open ports
  • port 8080: Alt HTTP — dev/admin panels, actuator.
» Confirmed leads from nuclei — triage these first
  • https://testphp.vulnweb.com/product.php
  • https://testphp.vulnweb.com/pictures/
  • https://rest.vulnweb.com/
» Recommended playbooks to run next
  • Broken Access Control / Privilege Escalation   ->  huntkit ideas bac
  • IDOR / Broken Object-Level Auth                 ->  huntkit ideas idor
  • SQL / NoSQL Injection                           ->  huntkit ideas sqli
  • Server-Side Request Forgery                     ->  huntkit ideas ssrf
  • Server-Side Template Injection                  ->  huntkit ideas ssti
  • Cross-Site Scripting                            ->  huntkit ideas xss
```

Those aren't hardcoded — they come from the actual data. `testphp.vulnweb.com`
exposes `listproducts.php?cat=1`, `artists.php?artist=2`, `userinfo.php?uid=1`
(textbook SQLi/IDOR surface) and HuntKit surfaces exactly that.

## 6. Pull a full checklist for one bug class

```console
$ huntkit ideas sqli
╭───────────────────────╮
│ SQL / NoSQL Injection │
╰───────────────────────╯
› When: Any parameter that reaches a data store: search, filters, sort, ids.
» Checklist
  • 1. Baseline each param, then probe with ' " ) and boolean/time payloads.
  • 2. Watch for error-based, boolean-based, and time-based differences.
  • 3. Test JSON and header inputs, not only query strings.
  • 4. For NoSQL, try operator injection ([$ne], [$gt]) and JSON bodies.
  • 5. Confirm carefully and stop at PoC — never dump/modify production data.
» Go-to tools
  • sqlmap (with --level tuned), Burp, nuclei
```

## 7. Scan (when the toolchain is installed)

```console
$ huntkit scan -p vulnweb -t nuclei
» nuclei vulnerability scan
✓ 3 nuclei findings -> scans/nuclei.txt
  • [php-errors]  [low]  https://testphp.vulnweb.com/product.php
  • [dir-listing] [info] https://testphp.vulnweb.com/pictures/
  • [swagger-api] [info] https://rest.vulnweb.com/
```

## 8. Report

```console
$ huntkit report -p vulnweb
✓ report written -> ~/.huntkit/vulnweb/reports/report_20260718_123915.md
› latest copy      -> ~/.huntkit/vulnweb/reports/latest.md
```

Produces a clean markdown report — scope, summary counts, nuclei findings,
live hosts, parameterised URLs, and a full activity log:

```markdown
# Recon report — vulnweb

## Scope
**In scope:**
- testphp.vulnweb.com
- *.vulnweb.com

## Summary
| Metric | Count |
| --- | --- |
| subdomains | 3 |
| live | 2 |
| urls | 9 |
| nuclei findings | 3 |

## nuclei findings
- `[php-errors] [http] [low] https://testphp.vulnweb.com/product.php`
- `[dir-listing] [http] [info] https://testphp.vulnweb.com/pictures/`
- `[swagger-api] [http] [info] https://rest.vulnweb.com/`
...
```

---

## The loop

```
init (scope) → recon → ideas (read it) → scan → ideas <class> (checklist)
             → test manually in Burp → report
```

One workspace → `-p` is inferred, so day-to-day it's just `huntkit recon <domain>`,
`huntkit ideas`, `huntkit report`.

> ⚠️ Authorised testing only — run HuntKit against assets you own or that are
> explicitly in scope for a bug bounty program / signed engagement.
