"""A bounded, scheme-guarded HTTP probe.

One GET, a short timeout, a capped body read, and no exception on failure: a
transport error or a refused scheme comes back as status 0 so the caller can
treat it as "could not confirm" rather than crashing a sweep. Only http(s) URLs
are opened, matching the fetchers in huntkit/enrich and huntkit/notify.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

_ALLOWED_SCHEMES = ("http", "https")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects: a 3xx target could point off the in-scope
    host (SSRF) or to a non-http(s) scheme, so the probe judges the 3xx itself."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


@dataclass(frozen=True)
class Probe:
    """The outcome of one probe. status is 0 on a transport error or bad scheme."""

    url: str
    status: int
    body: str
    content_type: str
    size: int


def _read(resp: object, max_bytes: int) -> tuple[str, str, int]:
    raw: bytes = resp.read(max_bytes)  # type: ignore[attr-defined]
    content_type = ""
    headers = getattr(resp, "headers", None)
    if headers is not None:
        content_type = headers.get("Content-Type", "") or ""
    return raw.decode("utf-8", "replace"), content_type, len(raw)


def probe(
    url: str,
    *,
    timeout: float = 10.0,
    max_bytes: int = 65536,
    user_agent: str = "",
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
) -> Probe:
    """GET ``url`` and capture the response, or return status 0 on any failure."""
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        return Probe(url, 0, "", "", 0)

    hdrs = dict(headers or {})
    if user_agent:
        hdrs.setdefault("User-Agent", user_agent)
    req = urllib.request.Request(url, headers=hdrs, method="GET")

    handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({scheme: proxy}))
    opener = urllib.request.build_opener(*handlers)

    try:
        # scheme is guarded to http(s) above
        with opener.open(req, timeout=timeout) as resp:  # nosec B310
            body, content_type, size = _read(resp, max_bytes)
            return Probe(url, getattr(resp, "status", 0) or 0, body, content_type, size)
    except urllib.error.HTTPError as exc:
        body, content_type, size = _read(exc, max_bytes)
        return Probe(url, exc.code, body, content_type, size)
    except (urllib.error.URLError, OSError, ValueError):
        return Probe(url, 0, "", "", 0)
