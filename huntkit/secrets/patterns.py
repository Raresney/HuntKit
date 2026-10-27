"""Secret-pattern catalog + JS endpoint extraction.

A declarative set of regexes for high-signal credential leaks — the same
"add a row, not a branch" ethos as the signal and playbook catalogs. Each
pattern names the capture group holding the secret so the scanner can redact
exactly that span, and an optional Shannon-entropy floor to drop low-entropy
false positives on the generic patterns.

Pure and offline: it matches text the operator already gathered (JS bundles,
config dumps, responses) and never touches a target.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from ..utils.severity import Severity


@dataclass(frozen=True)
class SecretPattern:
    id: str
    title: str
    severity: Severity
    regex: re.Pattern
    group: int = 0  # capture group holding the secret value
    min_entropy: float = 0.0  # skip matches below this Shannon entropy (0 = off)


def shannon_entropy(s: str) -> float:
    """Bits-per-character Shannon entropy — high for random keys, low for words."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _c(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


# Ordered most-specific (unique prefixes) → most-generic (keyword + entropy).
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "aws-access-key", "AWS access key id", Severity.CRITICAL, _c(r"\b(AKIA[0-9A-Z]{16})\b"), 1
    ),
    SecretPattern(
        "aws-secret-key",
        "AWS secret access key",
        Severity.CRITICAL,
        _c(r"(?i)aws.{0,24}?['\"]([A-Za-z0-9/+=]{40})['\"]"),
        1,
        4.0,
    ),
    SecretPattern(
        "gcp-api-key", "Google API key", Severity.HIGH, _c(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), 1
    ),
    SecretPattern(
        "gcp-oauth",
        "Google OAuth access token",
        Severity.HIGH,
        _c(r"\b(ya29\.[0-9A-Za-z\-_]{20,})"),
    ),
    SecretPattern(
        "github-token", "GitHub token", Severity.CRITICAL, _c(r"\b(gh[opsu]_[0-9A-Za-z]{36})\b"), 1
    ),
    SecretPattern(
        "github-pat",
        "GitHub fine-grained PAT",
        Severity.CRITICAL,
        _c(r"\b(github_pat_[0-9A-Za-z_]{82})\b"),
        1,
    ),
    SecretPattern(
        "slack-token", "Slack token", Severity.HIGH, _c(r"\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b"), 1
    ),
    SecretPattern(
        "slack-webhook",
        "Slack incoming webhook",
        Severity.MEDIUM,
        _c(r"(https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+)"),
        1,
    ),
    SecretPattern(
        "stripe-live",
        "Stripe live secret key",
        Severity.CRITICAL,
        _c(r"\b(sk_live_[0-9A-Za-z]{24,})\b"),
        1,
    ),
    SecretPattern(
        "stripe-test",
        "Stripe test secret key",
        Severity.LOW,
        _c(r"\b(sk_test_[0-9A-Za-z]{24,})\b"),
        1,
    ),
    SecretPattern(
        "openai-key",
        "OpenAI API key",
        Severity.HIGH,
        _c(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b"),
        1,
        3.5,
    ),
    SecretPattern("twilio-key", "Twilio API key", Severity.HIGH, _c(r"\b(SK[0-9a-fA-F]{32})\b"), 1),
    SecretPattern(
        "mailgun-key", "Mailgun API key", Severity.HIGH, _c(r"\b(key-[0-9a-zA-Z]{32})\b"), 1
    ),
    SecretPattern(
        "npm-token", "npm access token", Severity.HIGH, _c(r"\b(npm_[0-9A-Za-z]{36})\b"), 1
    ),
    SecretPattern(
        "private-key",
        "Private key block",
        Severity.CRITICAL,
        _c(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)"),
        1,
    ),
    SecretPattern(
        "jwt",
        "JSON Web Token",
        Severity.MEDIUM,
        _c(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
        1,
    ),
    SecretPattern(
        "generic-secret",
        "Hardcoded secret / key",
        Severity.MEDIUM,
        _c(
            r"(?i)(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)"
            r"['\"]?\s*[:=]\s*['\"]([0-9A-Za-z\-_./+=]{12,})['\"]"
        ),
        1,
        3.2,
    ),
)


# JS endpoint / path extraction — quoted paths and absolute URLs in script text.
ENDPOINT_RE = re.compile(r"""['"`](/[\w.\-/?=&%:@~]{2,}|https?://[\w.\-/?=&%:@~]+)['"`]""")

# Static-asset extensions that are noise when hunting for API endpoints.
_NOISE_EXT = (
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".ico",
    ".map",
)


def extract_endpoints(text: str) -> list[str]:
    """Pull API-ish paths and URLs out of JS text, de-duped, asset noise dropped."""
    found: list[str] = []
    for m in ENDPOINT_RE.finditer(text):
        ep = m.group(1)
        if ep.lower().rsplit("?", 1)[0].endswith(_NOISE_EXT):
            continue
        found.append(ep)
    return list(dict.fromkeys(found))
