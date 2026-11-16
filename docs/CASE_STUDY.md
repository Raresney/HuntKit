# Case study — recon → SARIF → GitHub Security tab

A real HuntKit run against **`scanme.nmap.org`**, Nmap's public host that
[explicitly authorises scanning](https://nmap.org/book/toc.html), end to end:
drive the toolchain, score the surface, and emit a SARIF document that GitHub's
code scanning renders in the **Security ▸ Code scanning** tab.

> **Authorised target.** `scanme.nmap.org` is maintained by the Nmap project for
> exactly this — trying a scanner against it. Everything below is HuntKit's own
> output on that host; nothing was exploited. The signals are *leads to verify*,
> not confirmed vulnerabilities.

## The run

Run with the published full-toolchain image, so every recon tool is present and
nothing has to be installed first:

```bash
docker run --rm -v "$PWD:/work" -w /work --entrypoint sh \
  ghcr.io/raresney/huntkit:latest -ec '
    huntkit init scanme --scope scanme.nmap.org
    huntkit recon scanme.nmap.org -p scanme
    huntkit analyze -p scanme
    huntkit report  -p scanme -f sarif -o /work/scanme.sarif
  '
```

## What recon found

One host, two open ports, and a sizeable URL surface pulled from passive and
active sources:

| Stage      | Count | Tools                                         |
| ---------- | ----: | --------------------------------------------- |
| subdomains |     1 | assetfinder, subfinder, findomain, amass      |
| resolved   |     1 | dnsx                                          |
| live       |     1 | httpx                                         |
| ports      |     2 | naabu                                         |
| urls       |   168 | hakrawler, waybackurls, katana, gau           |

HuntKit then scored the surface — **1 host, priority High, score 17, 6 signals**
— and pointed it at three playbooks: `authn`, `bac`, `ssti`.

## The SARIF

`report -f sarif` turned those six signals into a valid
[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) document. Each signal becomes
a result located at the affected host, with the severity driving both the SARIF
`level` and GitHub's `security-severity` score, plus a stable fingerprint so a
tracker can de-dupe across runs. The real artifact is checked in at
[`examples/scanme.nmap.org.sarif`](../examples/scanme.nmap.org.sarif):

| Rule            | level     | severity      | category | finding                                        |
| --------------- | --------- | ------------- | -------- | ---------------------------------------------- |
| `svn-exposed`   | error     | high          | path     | Exposed `.svn` directory                       |
| `admin-panel`   | warning   | medium        | path     | Admin path — privileged surface                |
| `joomla-admin`  | warning   | medium        | path     | Joomla administrator panel                     |
| `apache-status` | warning   | medium        | path     | Apache `server-status` — request / IP leak     |
| `lfi-param`     | warning   | medium        | param    | File / template parameter — test LFI & SSTI    |
| `ssh-open`      | note      | informational | port     | SSH exposed — version / CVE check              |

`error` → GitHub flags it High, `warning` → Medium, `note` → Note, so the run
lands in the Security tab already triaged by severity.

## Reaching the Security tab

The SARIF only has to be uploaded. The [reusable Action](../action.yml) does the
whole sweep and hands the file to `github/codeql-action/upload-sarif`, so a
scheduled or manual workflow drops the findings straight into code scanning —
see [`examples/code-scanning.yml`](../examples/code-scanning.yml) for the
consumer pattern.

This repository ships a one-click reproduction of exactly this case study:
[`.github/workflows/demo-scan.yml`](../.github/workflows/demo-scan.yml). From the
**Actions** tab, pick *Demo scan → Security tab* and **Run workflow**; when it
finishes, the six findings above appear under **Security ▸ Code scanning**.
