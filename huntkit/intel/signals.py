"""Signal catalog + matchers — the rule base of the intelligence engine.

Each rule turns one concrete observation (an open port, a URL path, a query
parameter, a subdomain label) into a typed :class:`Signal` carrying a
**severity** and the bug-class **playbooks** worth trying there. Rules are
plain data, so sharpening HuntKit's intelligence is a one-line edit — the
same "add a row, not a branch" ethos as the plugin registry.

Everything here is pure and offline: it reasons over recon output HuntKit
already gathered and never touches the target.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from urllib.parse import parse_qsl, urlsplit


class Severity(IntEnum):
    """Ordered so signals can be compared and aggregated numerically."""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return "informational" if self is Severity.INFO else self.name.lower()

    @property
    def style(self) -> str:  # matches the theme keys in utils.terminal
        return self.label


@dataclass(frozen=True)
class Signal:
    """One scored observation about one host."""

    id: str
    title: str
    severity: Severity
    category: str          # port | path | param | subdomain
    host: str
    evidence: str          # a representative hit (first seen)
    playbooks: tuple[str, ...] = ()
    count: int = 1         # how many raw hits collapsed into this signal

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category,
            "host": self.host,
            "evidence": self.evidence,
            "count": self.count,
            "playbooks": list(self.playbooks),
        }


@dataclass(frozen=True)
class Rule:
    """A catalog entry: what a match means, how bad, and what to try."""

    id: str
    title: str
    severity: Severity
    playbooks: tuple[str, ...] = ()


# --------------------------------------------------------------------------
# Port rules — keyed by port number. Unauthenticated-by-default datastores
# (redis/mongo/elastic/docker) are Critical; authenticated DBs are High;
# alternate HTTP ports are Low (just extra attack surface).
# --------------------------------------------------------------------------
PORT_RULES: dict[str, Rule] = {
    "21": Rule("ftp-open", "FTP exposed — anon login / plaintext creds", Severity.MEDIUM),
    "22": Rule("ssh-open", "SSH exposed — version/CVE check", Severity.INFO),
    "23": Rule("telnet-open", "Telnet exposed — plaintext, near-always a finding", Severity.HIGH),
    "25": Rule("smtp-open", "SMTP exposed — open relay / user enum", Severity.LOW),
    "110": Rule("pop3-open", "POP3 exposed — plaintext auth", Severity.LOW),
    "135": Rule("msrpc-open", "MSRPC exposed", Severity.MEDIUM),
    "139": Rule("netbios-open", "NetBIOS exposed", Severity.MEDIUM),
    "445": Rule("smb-open", "SMB exposed — null session / share enum", Severity.HIGH),
    "1433": Rule("mssql-open", "MSSQL exposed — auth & injection surface", Severity.HIGH, ("sqli",)),
    "1521": Rule("oracle-open", "Oracle DB exposed", Severity.HIGH, ("sqli",)),
    "2375": Rule("docker-open", "Docker API exposed — unauth = host RCE", Severity.CRITICAL),
    "2379": Rule("etcd-open", "etcd exposed — cluster secrets", Severity.HIGH),
    "3306": Rule("mysql-open", "MySQL exposed — auth surface, remote root?", Severity.HIGH, ("sqli",)),
    "3389": Rule("rdp-open", "RDP exposed — CVE/BlueKeep, cred-spray risk", Severity.HIGH),
    "5432": Rule("postgres-open", "PostgreSQL exposed — auth surface", Severity.HIGH, ("sqli",)),
    "5601": Rule("kibana-open", "Kibana exposed — often unauth data access", Severity.HIGH, ("authn",)),
    "5900": Rule("vnc-open", "VNC exposed — weak/no auth", Severity.HIGH),
    "6379": Rule("redis-open", "Redis exposed — frequently unauth = RCE", Severity.CRITICAL),
    "8000": Rule("http-alt-8000", "Alt HTTP (8000) — dev/admin apps", Severity.LOW, ("bac",)),
    "8080": Rule("http-alt-8080", "Alt HTTP (8080) — dev/admin panels, actuator", Severity.LOW, ("bac",)),
    "8443": Rule("https-alt-8443", "Alt HTTPS (8443) — staging apps, weaker auth", Severity.LOW, ("bac",)),
    "8888": Rule("http-alt-8888", "Alt HTTP (8888) — notebooks/dev apps", Severity.LOW, ("bac",)),
    "9000": Rule("http-alt-9000", "Port 9000 — SonarQube/PHP-FPM/consoles", Severity.MEDIUM),
    "9200": Rule("elastic-open", "Elasticsearch exposed — often unauth data dump", Severity.CRITICAL),
    "9300": Rule("elastic-transport", "Elasticsearch transport exposed", Severity.HIGH),
    "11211": Rule("memcached-open", "Memcached exposed — unauth, DDoS amp", Severity.HIGH),
    "15672": Rule("rabbitmq-open", "RabbitMQ mgmt exposed — default creds", Severity.MEDIUM, ("authn",)),
    "27017": Rule("mongo-open", "MongoDB exposed — often no auth", Severity.CRITICAL),
    "6443": Rule("kube-api", "Kubernetes API exposed", Severity.HIGH),
    "10250": Rule("kubelet-open", "Kubelet exposed — unauth exec risk", Severity.HIGH),
}


# --------------------------------------------------------------------------
# Path rules — needle (lowercase) found in a URL path -> Signal. Ordered
# roughly most→least specific; every independent match becomes its own signal.
# --------------------------------------------------------------------------
PATH_RULES: tuple[tuple[str, Rule], ...] = (
    ("/.git/", Rule("git-exposed", "Exposed .git directory — source/secret leak", Severity.HIGH)),
    ("/.svn/", Rule("svn-exposed", "Exposed .svn directory", Severity.HIGH)),
    ("/.hg/", Rule("hg-exposed", "Exposed .hg directory", Severity.HIGH)),
    ("/.env", Rule("env-exposed", "Exposed .env — credentials/secrets", Severity.CRITICAL)),
    ("/.aws/", Rule("aws-creds", "Exposed .aws directory — cloud credentials", Severity.CRITICAL)),
    ("/.htaccess", Rule("htaccess", "Exposed .htaccess", Severity.MEDIUM)),
    ("/.ds_store", Rule("dsstore", "Exposed .DS_Store — path disclosure", Severity.LOW)),
    ("/actuator", Rule("spring-actuator", "Spring Actuator — env/heapdump/SSRF surface", Severity.HIGH, ("ssrf",))),
    ("/phpmyadmin", Rule("phpmyadmin", "phpMyAdmin panel exposed", Severity.HIGH, ("authn", "sqli"))),
    ("/adminer", Rule("adminer", "Adminer DB panel exposed", Severity.HIGH, ("authn", "sqli"))),
    ("/jenkins", Rule("jenkins", "Jenkins exposed — script console / CVEs", Severity.HIGH, ("authn",))),
    ("/wp-admin", Rule("wp-admin", "WordPress admin — enum, weak plugin CVEs", Severity.MEDIUM, ("authn", "bac"))),
    ("/wp-login", Rule("wp-login", "WordPress login — brute/enum surface", Severity.MEDIUM, ("authn",))),
    ("/wp-json", Rule("wp-json", "WordPress REST API — user enum / authz", Severity.LOW, ("bac",))),
    ("/xmlrpc.php", Rule("xmlrpc", "WordPress xmlrpc — brute/pingback SSRF", Severity.MEDIUM, ("authn", "ssrf"))),
    ("/administrator", Rule("joomla-admin", "Joomla administrator panel", Severity.MEDIUM, ("authn", "bac"))),
    ("/graphql", Rule("graphql", "GraphQL — introspection, batching, field authz", Severity.MEDIUM, ("bac", "idor"))),
    ("/swagger", Rule("swagger", "Swagger UI — full endpoint map to test authz", Severity.LOW, ("bac", "idor"))),
    ("/api-docs", Rule("api-docs", "API docs exposed — endpoint map", Severity.LOW, ("bac", "idor"))),
    ("/openapi", Rule("openapi", "OpenAPI spec exposed — endpoint map", Severity.LOW, ("bac", "idor"))),
    ("/server-status", Rule("apache-status", "Apache server-status — request/IP leak", Severity.MEDIUM)),
    ("/phpinfo", Rule("phpinfo", "phpinfo() exposed — env/config disclosure", Severity.MEDIUM)),
    ("/console", Rule("web-console", "Web console endpoint", Severity.MEDIUM, ("bac",))),
    ("/debug", Rule("debug-endpoint", "Debug endpoint — verbose errors/state", Severity.MEDIUM)),
    ("/admin", Rule("admin-panel", "Admin path — privileged surface", Severity.MEDIUM, ("authn", "bac"))),
    ("/internal", Rule("internal-path", "Internal path — should not be public", Severity.MEDIUM, ("bac",))),
    ("/backup", Rule("backup-path", "Backup path — exposed archives/dumps", Severity.MEDIUM)),
    ("/.well-known/security.txt", Rule("securitytxt", "security.txt present", Severity.INFO)),
    (".sql", Rule("sql-dump", "SQL dump in URL — data exposure", Severity.HIGH)),
    (".bak", Rule("bak-file", "Backup file (.bak) in URL", Severity.MEDIUM)),
    (".zip", Rule("archive-file", "Archive (.zip) in URL — possible source/backup", Severity.LOW)),
    (".tar.gz", Rule("targz-file", "Archive (.tar.gz) in URL", Severity.LOW)),
    (".log", Rule("log-file", "Log file in URL — info disclosure", Severity.LOW)),
)


# --------------------------------------------------------------------------
# Param rules — grouped param names -> Rule. Built into a name->rule map with
# "first group wins", so higher-impact classes (listed first) take priority
# when a name could belong to several.
# --------------------------------------------------------------------------
_PARAM_RULES: tuple[tuple[tuple[str, ...], Rule], ...] = (
    (("cmd", "exec", "command", "execute", "run", "ping", "code", "shell", "daemon", "cli"),
     Rule("cmd-param", "Command-like parameter — probe for RCE", Severity.HIGH)),
    (("url", "uri", "link", "redirect", "redir", "redirect_uri", "redirect_url", "next",
      "dest", "destination", "return", "returnurl", "return_url", "continue", "callback",
      "webhook", "feed", "forward", "out", "to", "imageurl", "image_url", "proxy", "fetch",
      "load", "site", "domain", "host", "open"),
     Rule("ssrf-param", "URL/redirect parameter — test SSRF & open-redirect", Severity.MEDIUM, ("ssrf",))),
    (("password", "passwd", "pwd", "pass", "token", "access_token", "api_key", "apikey",
      "secret", "auth", "authorization", "session", "sessionid", "jwt", "key"),
     Rule("secret-param", "Secret in query string — credential exposure", Severity.MEDIUM, ("authn",))),
    (("file", "filename", "path", "template", "include", "page", "doc", "document", "folder",
      "dir", "root", "download", "pdf", "style", "lang", "view"),
     Rule("lfi-param", "File/template parameter — test LFI/traversal & SSTI", Severity.MEDIUM, ("ssti",))),
    (("filter", "sort", "order", "orderby", "order_by", "where", "column", "select", "field", "sortby"),
     Rule("sqli-param", "Filter/sort parameter — reaches the data store", Severity.LOW, ("sqli",))),
    (("q", "s", "search", "query", "keyword", "kw", "term", "name", "title", "comment",
      "message", "msg", "content", "description", "desc", "feedback", "body", "text", "subject"),
     Rule("reflect-param", "Reflected text parameter — test XSS & SQLi", Severity.LOW, ("xss", "sqli"))),
    (("id", "uid", "user", "userid", "user_id", "account", "accountid", "account_id",
      "orderid", "order_id", "invoice", "number", "pid", "gid", "item", "itemid", "cart",
      "profile", "customer", "customerid", "groupid", "record", "ref"),
     Rule("idor-param", "Object-id parameter — test IDOR / BOLA", Severity.LOW, ("idor",))),
    (("xml", "data", "input", "xmlfile"),
     Rule("xxe-param", "XML/data parameter — test XXE", Severity.LOW)),
)

PARAM_MAP: dict[str, Rule] = {}
for _names, _rule in _PARAM_RULES:
    for _n in _names:
        PARAM_MAP.setdefault(_n, _rule)


# --------------------------------------------------------------------------
# Subdomain-label rules — a label in the host (e.g. "dev" in dev.api.x.com)
# hints at weaker controls or a named service. Matched exact-first, then by
# longest prefix ("dev01" -> dev).
# --------------------------------------------------------------------------
LABEL_RULES: tuple[tuple[str, Rule], ...] = (
    ("dev", Rule("nonprod-host", "Non-prod host — typically weaker controls", Severity.MEDIUM, ("authn", "bac"))),
    ("test", Rule("nonprod-host", "Non-prod host — typically weaker controls", Severity.MEDIUM, ("authn", "bac"))),
    ("staging", Rule("nonprod-host", "Staging host — typically weaker controls", Severity.MEDIUM, ("authn", "bac"))),
    ("stage", Rule("nonprod-host", "Staging host — typically weaker controls", Severity.MEDIUM, ("authn", "bac"))),
    ("stg", Rule("nonprod-host", "Staging host — typically weaker controls", Severity.MEDIUM, ("authn", "bac"))),
    ("uat", Rule("nonprod-host", "UAT host — typically weaker controls", Severity.MEDIUM, ("authn", "bac"))),
    ("qa", Rule("nonprod-host", "QA host — typically weaker controls", Severity.MEDIUM, ("authn", "bac"))),
    ("preprod", Rule("nonprod-host", "Pre-prod host — typically weaker controls", Severity.MEDIUM, ("authn", "bac"))),
    ("sandbox", Rule("nonprod-host", "Sandbox host — typically weaker controls", Severity.MEDIUM, ("authn", "bac"))),
    ("demo", Rule("nonprod-host", "Demo host — often stale/loose", Severity.LOW, ("authn", "bac"))),
    ("beta", Rule("nonprod-host", "Beta host — often stale/loose", Severity.LOW, ("authn", "bac"))),
    ("old", Rule("legacy-host", "Legacy host — unpatched, forgotten", Severity.MEDIUM, ("authn", "bac"))),
    ("legacy", Rule("legacy-host", "Legacy host — unpatched, forgotten", Severity.MEDIUM, ("authn", "bac"))),
    ("backup", Rule("legacy-host", "Backup host — stale data/config", Severity.MEDIUM)),
    ("admin", Rule("admin-host", "Admin host — privileged surface", Severity.MEDIUM, ("authn", "bac"))),
    ("internal", Rule("internal-host", "Internal host exposed publicly", Severity.MEDIUM, ("bac",))),
    ("intranet", Rule("internal-host", "Intranet host exposed publicly", Severity.MEDIUM, ("bac",))),
    ("corp", Rule("internal-host", "Corporate host exposed publicly", Severity.LOW, ("bac",))),
    ("vpn", Rule("vpn-host", "VPN endpoint — known-CVE surface", Severity.MEDIUM, ("authn",))),
    ("remote", Rule("remote-host", "Remote-access host", Severity.MEDIUM, ("authn",))),
    ("jenkins", Rule("ci-host", "Jenkins/CI host — script console/CVEs", Severity.HIGH, ("authn",))),
    ("gitlab", Rule("git-host", "GitLab host — auth/authz & CVEs", Severity.HIGH, ("authn", "bac"))),
    ("git", Rule("git-host", "Git host — source/auth surface", Severity.MEDIUM, ("authn",))),
    ("jira", Rule("atlassian-host", "Jira host — known SSRF/unauth CVEs", Severity.MEDIUM, ("ssrf", "bac"))),
    ("confluence", Rule("atlassian-host", "Confluence host — known RCE/SSRF CVEs", Severity.MEDIUM, ("ssrf", "bac"))),
    ("grafana", Rule("dashboard-host", "Grafana host — auth bypass CVEs", Severity.MEDIUM, ("authn",))),
    ("kibana", Rule("dashboard-host", "Kibana host — often unauth data", Severity.HIGH, ("authn",))),
    ("pma", Rule("db-admin-host", "DB admin host (phpMyAdmin)", Severity.HIGH, ("authn", "sqli"))),
    ("phpmyadmin", Rule("db-admin-host", "DB admin host (phpMyAdmin)", Severity.HIGH, ("authn", "sqli"))),
    ("api", Rule("api-host", "API host — object-level authz surface", Severity.LOW, ("idor", "bac"))),
    ("gateway", Rule("api-host", "Gateway host — routing/authz surface", Severity.LOW, ("bac",))),
    ("portal", Rule("portal-host", "Portal host — multi-role authz surface", Severity.LOW, ("authn", "bac"))),
    ("mail", Rule("mail-host", "Mail host — webmail/auth surface", Severity.LOW, ("authn",))),
    ("webmail", Rule("mail-host", "Webmail host — auth surface", Severity.LOW, ("authn",))),
    ("ftp", Rule("ftp-host", "FTP host — plaintext/anon surface", Severity.MEDIUM)),
    ("s3", Rule("storage-host", "Storage host — bucket ACL / takeover", Severity.LOW, ("subtakeover",))),
    ("storage", Rule("storage-host", "Storage host — bucket ACL / takeover", Severity.LOW, ("subtakeover",))),
    ("assets", Rule("storage-host", "Assets host — dangling-CNAME takeover", Severity.LOW, ("subtakeover",))),
    ("cdn", Rule("storage-host", "CDN host — dangling-CNAME takeover", Severity.LOW, ("subtakeover",))),
    ("static", Rule("storage-host", "Static host — dangling-CNAME takeover", Severity.LOW, ("subtakeover",))),
)

_LABEL_MAP: dict[str, Rule] = {}
for _key, _r in LABEL_RULES:
    _LABEL_MAP.setdefault(_key, _r)


# --------------------------------------------------------------------------
# URL helpers
# --------------------------------------------------------------------------
def url_host(url: str) -> str:
    """Hostname of a URL, lowercased; '' if unparseable. Scheme optional."""
    url = url.strip()
    if not url:
        return ""
    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        return (parts.hostname or "").lower()
    except ValueError:
        return ""


def _url_path(url: str) -> str:
    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        return (parts.path or "").lower()
    except ValueError:
        return ""


def _url_params(url: str) -> list[str]:
    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        return [name for name, _ in parse_qsl(parts.query, keep_blank_values=True)]
    except ValueError:
        return []


def _label_rule(label: str) -> Rule | None:
    """Exact label match, else the longest-prefix rule (>=3 chars)."""
    rule = _LABEL_MAP.get(label)
    if rule is not None:
        return rule
    best: Rule | None = None
    best_len = 0
    for key, r in LABEL_RULES:
        if len(key) >= 3 and label.startswith(key) and len(key) > best_len:
            best, best_len = r, len(key)
    return best


# --------------------------------------------------------------------------
# Accumulator — collapse many raw hits into one signal per (host, rule).
# --------------------------------------------------------------------------
class _Acc:
    def __init__(self) -> None:
        self._map: dict[tuple[str, str], list] = {}

    def add(self, host: str, rule: Rule, category: str, evidence: str) -> None:
        key = (host, rule.id)
        entry = self._map.get(key)
        if entry is None:
            self._map[key] = [rule, category, evidence, 1]
        else:
            entry[3] += 1

    def signals(self) -> list[Signal]:
        out = []
        for (host, _id), (rule, category, evidence, count) in self._map.items():
            out.append(Signal(
                id=rule.id, title=rule.title, severity=rule.severity,
                category=category, host=host, evidence=evidence,
                playbooks=rule.playbooks, count=count,
            ))
        return out


# --------------------------------------------------------------------------
# Matchers — each pure, each returns deduped signals.
# --------------------------------------------------------------------------
def signals_from_ports(lines: list[str]) -> list[Signal]:
    """`host:port` lines -> port signals."""
    acc = _Acc()
    for line in lines:
        host, sep, port = line.strip().rpartition(":")
        if not sep or not port.isdigit():
            continue
        rule = PORT_RULES.get(port)
        if rule is not None:
            host = host.strip().lower()
            acc.add(host, rule, "port", f"{host}:{port}")
    return acc.signals()


def signals_from_paths(urls: list[str]) -> list[Signal]:
    """URLs -> path signals (interesting endpoints/files)."""
    acc = _Acc()
    for url in urls:
        host = url_host(url)
        if not host:
            continue
        path = _url_path(url)
        if not path:
            continue
        for needle, rule in PATH_RULES:
            if needle in path:
                acc.add(host, rule, "path", url.strip())
    return acc.signals()


def signals_from_params(urls: list[str]) -> list[Signal]:
    """URLs -> query-parameter signals (injection/SSRF/IDOR hints)."""
    acc = _Acc()
    for url in urls:
        host = url_host(url)
        if not host:
            continue
        for name in _url_params(url):
            rule = PARAM_MAP.get(name.lower())
            if rule is not None:
                acc.add(host, rule, "param", f"{name}= @ {url.strip()}")
    return acc.signals()


def signals_from_labels(hosts: list[str]) -> list[Signal]:
    """Hostnames -> subdomain-label signals (non-prod/named-service hints)."""
    acc = _Acc()
    for host in hosts:
        h = host.strip().lower()
        if not h:
            continue
        for label in h.split("."):
            rule = _label_rule(label)
            if rule is not None:
                acc.add(h, rule, "subdomain", h)
    return acc.signals()


def scan_signals(*, ports: list[str], urls: list[str], hosts: list[str]) -> list[Signal]:
    """Run every matcher over the recon inputs and return the flat signal set."""
    signals: list[Signal] = []
    signals += signals_from_ports(ports)
    signals += signals_from_paths(urls)
    signals += signals_from_params(urls)
    signals += signals_from_labels(hosts)
    return signals
