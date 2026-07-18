"""Methodology knowledge base + context-aware idea engine.

Two jobs:
  1. Static checklists per bug class (IDOR, XSS, SSRF, ...), so you can pull
     up a battle-tested attack plan for any category.
  2. A heuristic engine that reads the current workspace's recon output
     (detected tech, URLs, open ports) and suggests *specific* things to
     try next — the "where do I dig?" nudge.

This is guidance only. It reasons over data HuntKit already collected; it
never attacks anything on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import ui
from .workspace import Workspace


@dataclass
class Playbook:
    key: str
    title: str
    when: str                       # when to reach for this bug class
    checklist: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)


PLAYBOOKS: dict[str, Playbook] = {
    "idor": Playbook(
        "idor", "IDOR / Broken Object-Level Auth",
        "Any endpoint that takes an id/uuid/filename and returns object data.",
        [
            "Map every request carrying an object id (numeric, uuid, hash, email).",
            "Create two accounts; replay account A's requests with A's session but B's ids.",
            "Swap ids in path, query, body, JSON, and headers — not just the obvious one.",
            "Try encoded/wrapped ids: base64, hashids, ids inside a JWT or cookie.",
            "Change method (GET->POST/PUT/DELETE) on the same object id.",
            "Look for id leakage in list endpoints, exports, and error messages.",
            "Test mass-assignment: add fields like role, owner_id, is_admin to bodies.",
        ],
        ["Burp Repeater/Autorize", "arjun", "ffuf"],
    ),
    "bac": Playbook(
        "bac", "Broken Access Control / Privilege Escalation",
        "Multi-role apps, admin panels, tenant isolation.",
        [
            "Enumerate role-gated routes as a low-priv user (admin/, /internal, /api/v*/admin).",
            "Force-browse to admin endpoints; check for client-side-only auth.",
            "Replay privileged actions with a lower-priv token (vertical escalation).",
            "Cross-tenant: swap org/tenant id and access another tenant's data.",
            "Check for auth on the API but not on GraphQL/websocket/legacy endpoints.",
            "Look for referer/role headers the server trusts (X-Original-URL, X-Role).",
        ],
        ["Burp Autorize", "ffuf", "nuclei"],
    ),
    "xss": Playbook(
        "xss", "Cross-Site Scripting",
        "Any reflected/stored user input rendered in HTML/JS context.",
        [
            "Grep gathered URLs for reflected parameters; test canary strings first.",
            "Identify context: HTML body, attribute, JS string, URL, or DOM sink.",
            "For DOM XSS, trace sources (location, postMessage) to sinks (innerHTML, eval).",
            "Bypass filters: event handlers, SVG, mutation XSS, unicode/encoding tricks.",
            "Test stored surfaces: profile, comments, filenames, support tickets.",
            "Check CSP; a weak/absent CSP raises impact of any injection.",
        ],
        ["dalfox", "Burp", "kxss/gxss"],
    ),
    "ssrf": Playbook(
        "ssrf", "Server-Side Request Forgery",
        "URL/host/webhook/import/preview parameters, PDF/image render, integrations.",
        [
            "Find sinks: url=, redirect=, webhook, imageUrl, callback, import-from-url.",
            "Point at a collaborator/interactsh host; watch for DNS + HTTP callbacks.",
            "Try cloud metadata (169.254.169.254, GCP metadata w/ header) once a hit lands.",
            "Bypass SSRF filters: alt IP encodings, [::], DNS rebind, redirect chains.",
            "Test blind SSRF via timing and out-of-band, not just reflected responses.",
        ],
        ["interactsh/Burp Collaborator", "nuclei -tags ssrf"],
    ),
    "sqli": Playbook(
        "sqli", "SQL / NoSQL Injection",
        "Any parameter that reaches a data store: search, filters, sort, ids.",
        [
            "Baseline each param, then probe with ' \" ) and boolean/time payloads.",
            "Watch for error-based, boolean-based, and time-based differences.",
            "Test JSON and header inputs, not only query strings.",
            "For NoSQL, try operator injection ([$ne], [$gt]) and JSON bodies.",
            "Confirm carefully and stop at PoC — never dump/modify production data.",
        ],
        ["sqlmap (with --level tuned)", "Burp", "nuclei"],
    ),
    "ssti": Playbook(
        "ssti", "Server-Side Template Injection",
        "Rendered templates: emails, invoices, name/preview fields, error pages.",
        [
            "Inject polyglot {{7*7}} / ${7*7} / <%= 7*7 %> and look for 49.",
            "Fingerprint the engine (Jinja2, Twig, FreeMarker, Velocity) from behaviour.",
            "Escalate from math to object access carefully to prove impact.",
        ],
        ["tplmap", "Burp", "nuclei -tags ssti"],
    ),
    "subtakeover": Playbook(
        "subtakeover", "Subdomain Takeover",
        "CNAMEs pointing at deprovisioned cloud services.",
        [
            "Resolve every subdomain; flag CNAMEs to S3/GitHub Pages/Heroku/Azure/etc.",
            "Match error fingerprints (NoSuchBucket, 'There isn't a GitHub Pages site').",
            "Confirm you can actually claim the resource before reporting.",
        ],
        ["nuclei -tags takeover", "subjack", "dnsx"],
    ),
    "authn": Playbook(
        "authn", "Authentication / Session flaws",
        "Login, registration, reset, MFA, OAuth, JWT.",
        [
            "Test password reset: token entropy, host-header poisoning, reuse, no expiry.",
            "JWT: alg:none, weak secret (crack with wordlist), kid/jku injection.",
            "OAuth: redirect_uri validation, state/CSRF, token leakage in referer.",
            "Rate limit on login/OTP; account enumeration via timing/error diffs.",
            "Session fixation, missing rotation after privilege change, long-lived tokens.",
        ],
        ["Burp", "jwt_tool", "nuclei"],
    ),
    "cors": Playbook(
        "cors", "CORS misconfiguration",
        "APIs returning Access-Control-Allow-* headers.",
        [
            "Reflect Origin: send Origin: evil.com and check ACAO reflection.",
            "Test null origin and subdomain trust; combine with credentials:true.",
            "Confirm sensitive data is actually reachable cross-origin before reporting.",
        ],
        ["nuclei -tags cors", "curl", "Burp"],
    ),
}


# ---- static checklist output --------------------------------------------
def show_playbook(key: str) -> bool:
    pb = PLAYBOOKS.get(key.lower())
    if not pb:
        ui.error(f"unknown category '{key}'. Try: {', '.join(PLAYBOOKS)}")
        return False
    ui.banner(pb.title)
    ui.info(f"When: {pb.when}")
    ui.step("Checklist")
    for i, item in enumerate(pb.checklist, 1):
        ui.bullet(f"{i}. {item}")
    if pb.tools:
        ui.step("Go-to tools")
        ui.bullet(", ".join(pb.tools), "green")
    return True


def list_playbooks() -> None:
    ui.banner("HuntKit playbooks")
    ui.table(
        "",
        ["key", "class", "when"],
        [(pb.key, pb.title, pb.when) for pb in PLAYBOOKS.values()],
    )
    ui.info("Detail: huntkit ideas <key>   e.g.  huntkit ideas ssrf")


# ---- context-aware idea engine ------------------------------------------
# Map a detected technology (substring, lowercase) to bug classes worth a look.
TECH_HINTS: list[tuple[str, list[str], str]] = [
    ("wordpress", ["xss", "authn"], "WordPress: enum plugins/users, check xmlrpc, weak plugin CVEs (nuclei -tags wordpress)."),
    ("jira", ["ssrf", "bac"], "Jira: known SSRF/unauth CVEs — pin the exact version and check nuclei jira templates."),
    ("graphql", ["bac", "idor"], "GraphQL: introspection, batching, field-level authz, IDOR via node ids."),
    ("apache", ["ssrf"], "Apache: check mod_proxy/path traversal & version CVEs."),
    ("nginx", ["ssrf"], "nginx: alias traversal, misrouted proxy_pass, off-by-slash."),
    ("php", ["sqli", "xss", "ssti"], "PHP: classic injection surface — probe params for SQLi/LFI."),
    ("laravel", ["ssti", "authn"], "Laravel: debug mode (.env leak), APP_KEY, ignition RCE if debug on."),
    ("django", ["ssti", "bac"], "Django: DEBUG=True leaks, admin/, weak SECRET_KEY signing."),
    ("spring", ["ssrf", "ssti"], "Spring: actuator endpoints (/actuator/*), SpEL SSTI, Spring4Shell."),
    ("express", ["idor", "bac"], "Node/Express: prototype pollution, mass assignment, missing authz."),
    ("s3", ["subtakeover"], "S3 reference: check bucket ACLs and takeover on dangling CNAMEs."),
    ("cloudflare", [], "Behind Cloudflare: hunt for origin IP leaks (DNS history, SPF, dev subdomains)."),
    ("swagger", ["bac", "idor"], "Swagger/OpenAPI exposed: map every endpoint, test authz on each."),
    ("tomcat", ["authn"], "Tomcat: /manager default creds, path normalization bugs."),
    ("iis", ["ssrf"], "IIS: short-name (~) enumeration, ASP.NET viewstate, path tricks."),
]

# Interesting URL keywords -> bug classes.
URL_HINTS: list[tuple[str, list[str], str]] = [
    (r"[?&](url|uri|link|redirect|next|dest|domain|callback|webhook|feed|host)=",
     ["ssrf"], "Redirect/URL params -> test open-redirect and SSRF."),
    (r"[?&](id|user|account|uid|order|invoice|doc|file|pid)=",
     ["idor"], "Object-id params -> test IDOR / BOLA."),
    (r"[?&](q|s|search|query|name|title|comment|message)=",
     ["xss", "sqli"], "Reflected text params -> test XSS and SQLi."),
    (r"[?&](file|path|template|include|page|lang|view)=",
     ["ssti"], "File/template params -> test LFI/path traversal & SSTI."),
    (r"/(admin|internal|debug|actuator|console|api/v\d|graphql)",
     ["bac"], "Privileged/API paths -> test broken access control."),
    (r"\.(bak|old|zip|tar|gz|sql|env|git|config|log)(\b|$)",
     [], "Sensitive file extensions in URLs -> check for exposed backups/secrets."),
]


def suggest(ws: Workspace) -> None:
    """Read the workspace and print targeted, prioritised ideas."""
    ui.banner(f"HuntKit ideas — {ws.program}")

    counts = ws.state.get("counts", {})
    subs = counts.get("subdomains", 0)
    urls = counts.get("urls", 0)
    live = counts.get("live", 0)

    if not any([subs, urls, live]):
        ui.warn("no recon data yet. Run:  huntkit recon <domain>")
        ui.info("Meanwhile, browse the playbooks:  huntkit ideas list")
        return

    suggested_classes: set[str] = set()

    # --- from detected tech (httpx.txt) ---
    httpx_txt = ws.path("recon", "httpx.txt")
    if httpx_txt.exists():
        blob = httpx_txt.read_text(encoding="utf-8").lower()
        hits = []
        for needle, classes, note in TECH_HINTS:
            if needle in blob:
                hits.append(note)
                suggested_classes.update(classes)
        if hits:
            ui.step("Based on detected technology")
            for note in hits:
                ui.bullet(note, "green")

    # --- from gathered URLs ---
    urls_list = ws.read_lines("urls/all_urls.txt")
    if urls_list:
        blob = "\n".join(urls_list)
        ui.step("Based on gathered URLs")
        for pattern, classes, note in URL_HINTS:
            matches = re.findall(pattern, blob, re.IGNORECASE)
            if matches:
                ui.bullet(f"{note}  ({len(matches)} URL(s))", "green")
                suggested_classes.update(classes)

    # --- from open ports ---
    ports_txt = ws.path("recon", "ports.txt")
    if ports_txt.exists():
        interesting = _interesting_ports(ports_txt.read_text(encoding="utf-8"))
        if interesting:
            ui.step("Based on open ports")
            for note in interesting:
                ui.bullet(note, "green")

    # --- nuclei findings recap ---
    findings = ws.read_lines("scans/nuclei.txt")
    if findings:
        ui.step("Confirmed leads from nuclei — triage these first")
        for f in findings[:8]:
            ui.bullet(f, "yellow")

    # --- next-step playbooks ---
    if suggested_classes:
        ui.step("Recommended playbooks to run next")
        for key in sorted(suggested_classes):
            pb = PLAYBOOKS.get(key)
            if pb:
                ui.bullet(f"{pb.title}   ->  huntkit ideas {key}", "cyan")
    else:
        ui.info("No strong signal yet — widen recon (urls/ports) or pull a playbook: huntkit ideas list")


PORT_NOTES = {
    "21": "FTP open — anon login? plaintext creds.",
    "22": "SSH — version/CVE check, weak-cred spray only if in scope & allowed.",
    "23": "Telnet — plaintext, almost always a finding.",
    "25": "SMTP — open relay / user enum (VRFY).",
    "445": "SMB — enum shares/null session.",
    "1433": "MSSQL exposed — auth & injection surface.",
    "3306": "MySQL exposed — auth surface, remote root?",
    "3389": "RDP exposed — CVE/BlueKeep, cred spray risk.",
    "5432": "Postgres exposed — auth surface.",
    "6379": "Redis exposed — often no auth = RCE.",
    "8080": "Alt HTTP — dev/admin panels, actuator.",
    "8443": "Alt HTTPS — staging apps, weaker auth.",
    "9200": "Elasticsearch — frequently unauthenticated data exposure.",
    "27017": "MongoDB exposed — often no auth.",
}


def _interesting_ports(text: str) -> list[str]:
    notes = []
    seen = set()
    for line in text.splitlines():
        m = re.search(r":(\d+)", line)
        if not m:
            continue
        port = m.group(1)
        if port in PORT_NOTES and port not in seen:
            seen.add(port)
            notes.append(f"port {port}: {PORT_NOTES[port]}")
    return notes
