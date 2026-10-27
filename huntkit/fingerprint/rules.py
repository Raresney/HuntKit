"""CDN / WAF / cloud / tech fingerprint catalog.

Each rule maps one vendor to the HTTP response headers (and Set-Cookie values)
that give it away. A rule matches when ANY of its header signals hit — a header
is present and, if a value substring is given, contains it. Plain data, so
adding a vendor is one row (same ethos as the signal and secret catalogs).

Pure and offline: it classifies response headers the operator already captured
(``curl -sI``, a saved response). WAF matches are flagged MEDIUM because a WAF
changes how the rest of the engagement should be run; everything else is INFO.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..utils.severity import Severity

# kind values, in the order they should surface.
KINDS = ("waf", "cdn", "cloud", "server", "tech")


@dataclass(frozen=True)
class FingerprintRule:
    id: str
    name: str
    kind: str  # one of KINDS
    headers: tuple[tuple[str, str], ...]  # (header-name-lower, value-substr-lower); "" = presence
    severity: Severity = Severity.INFO


_WAF = Severity.MEDIUM
_INFO = Severity.INFO


FINGERPRINT_RULES: tuple[FingerprintRule, ...] = (
    # ---- WAF / security proxies (flagged) --------------------------------
    FingerprintRule(
        "imperva",
        "Imperva / Incapsula WAF",
        "waf",
        (
            ("x-iinfo", ""),
            ("x-cdn", "incapsula"),
            ("set-cookie", "incap_ses"),
            ("set-cookie", "visid_incap"),
        ),
        _WAF,
    ),
    FingerprintRule(
        "sucuri",
        "Sucuri CloudProxy WAF",
        "waf",
        (("x-sucuri-id", ""), ("x-sucuri-cache", ""), ("server", "sucuri/cloudproxy")),
        _WAF,
    ),
    FingerprintRule(
        "f5-bigip",
        "F5 BIG-IP / ASM",
        "waf",
        (("set-cookie", "bigipserver"), ("server", "big-ip"), ("x-waf-event-info", "")),
        _WAF,
    ),
    FingerprintRule(
        "citrix-netscaler",
        "Citrix NetScaler",
        "waf",
        (("set-cookie", "ns_af"), ("set-cookie", "citrix_ns_id"), ("via", "ns-cache")),
        _WAF,
    ),
    FingerprintRule(
        "barracuda",
        "Barracuda WAF",
        "waf",
        (("set-cookie", "barra_counter_session"), ("server", "barracuda")),
        _WAF,
    ),
    FingerprintRule("fortiweb", "Fortinet FortiWeb", "waf", (("set-cookie", "fortiwafsid"),), _WAF),
    FingerprintRule(
        "modsecurity",
        "ModSecurity",
        "waf",
        (("server", "mod_security"), ("server", "modsecurity")),
        _WAF,
    ),
    FingerprintRule("aws-waf", "AWS WAF", "waf", (("x-amzn-waf-action", ""),), _WAF),
    # ---- CDN -------------------------------------------------------------
    FingerprintRule(
        "cloudflare",
        "Cloudflare",
        "cdn",
        (("server", "cloudflare"), ("cf-ray", ""), ("cf-cache-status", "")),
        _INFO,
    ),
    FingerprintRule(
        "fastly",
        "Fastly",
        "cdn",
        (("x-served-by", "cache"), ("x-fastly-request-id", ""), ("via", "fastly")),
        _INFO,
    ),
    FingerprintRule(
        "cloudfront",
        "Amazon CloudFront",
        "cdn",
        (("via", "cloudfront"), ("x-amz-cf-id", ""), ("x-amz-cf-pop", "")),
        _INFO,
    ),
    FingerprintRule(
        "akamai",
        "Akamai",
        "cdn",
        (("server", "akamaighost"), ("x-akamai-transformed", ""), ("x-akamai-request-id", "")),
        _INFO,
    ),
    FingerprintRule("keycdn", "KeyCDN", "cdn", (("server", "keycdn-engine"),), _INFO),
    FingerprintRule("bunnycdn", "BunnyCDN", "cdn", (("server", "bunnycdn"),), _INFO),
    # ---- cloud / hosting -------------------------------------------------
    FingerprintRule(
        "aws-s3", "Amazon S3", "cloud", (("server", "amazons3"), ("x-amz-bucket-region", "")), _INFO
    ),
    FingerprintRule(
        "aws", "Amazon Web Services", "cloud", (("x-amz-request-id", ""), ("x-amz-id-2", "")), _INFO
    ),
    FingerprintRule(
        "gcp",
        "Google Cloud",
        "cloud",
        (("server", "gws"), ("server", "gse"), ("x-goog-generation", "")),
        _INFO,
    ),
    FingerprintRule(
        "azure",
        "Microsoft Azure",
        "cloud",
        (("x-azure-ref", ""), ("x-ms-request-id", ""), ("server", "microsoft-azure")),
        _INFO,
    ),
    FingerprintRule("heroku", "Heroku", "cloud", (("via", "vegur"), ("server", "cowboy")), _INFO),
    FingerprintRule(
        "vercel", "Vercel", "cloud", (("x-vercel-id", ""), ("server", "vercel")), _INFO
    ),
    FingerprintRule(
        "netlify", "Netlify", "cloud", (("x-nf-request-id", ""), ("server", "netlify")), _INFO
    ),
    FingerprintRule("github-pages", "GitHub Pages", "cloud", (("server", "github.com"),), _INFO),
    FingerprintRule(
        "fly-io", "Fly.io", "cloud", (("fly-request-id", ""), ("server", "fly")), _INFO
    ),
    FingerprintRule("render", "Render", "cloud", (("x-render-origin-server", ""),), _INFO),
    # ---- server / framework ---------------------------------------------
    FingerprintRule("nginx", "nginx", "server", (("server", "nginx"),), _INFO),
    FingerprintRule("apache", "Apache httpd", "server", (("server", "apache"),), _INFO),
    FingerprintRule("iis", "Microsoft IIS", "server", (("server", "microsoft-iis"),), _INFO),
    FingerprintRule("litespeed", "LiteSpeed", "server", (("server", "litespeed"),), _INFO),
    FingerprintRule("openresty", "OpenResty", "server", (("server", "openresty"),), _INFO),
    FingerprintRule("express", "Node.js / Express", "tech", (("x-powered-by", "express"),), _INFO),
    FingerprintRule("php", "PHP", "tech", (("x-powered-by", "php"),), _INFO),
    FingerprintRule(
        "aspnet", "ASP.NET", "tech", (("x-powered-by", "asp.net"), ("x-aspnet-version", "")), _INFO
    ),
    FingerprintRule(
        "nextjs", "Next.js", "tech", (("x-powered-by", "next.js"), ("x-nextjs-cache", "")), _INFO
    ),
    FingerprintRule(
        "wordpress", "WordPress", "tech", (("x-pingback", ""), ("link", "wp-json")), _INFO
    ),
    FingerprintRule("laravel", "Laravel", "tech", (("set-cookie", "laravel_session"),), _INFO),
    FingerprintRule("django", "Django", "tech", (("set-cookie", "csrftoken"),), _INFO),
)
