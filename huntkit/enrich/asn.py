"""ASN enrichment — map an in-scope host to the network that announces it.

Knowing the ASN and BGP prefix behind a host turns a single name into a block
of IP space to sweep: sibling origins, admin panels, and dev boxes frequently
live in the same prefix as the flagship site. HuntKit resolves the host to an
IP locally, then asks Team Cymru's IP-to-ASN WHOIS service for the mapping.

> That WHOIS call is the one place this layer sends data off the box — the
> *resolved IP* of an in-scope host is sent to ``whois.cymru.com``. It is a
> public, well-known lookup service, but it is third-party egress, so the CLI
> names it before running and both the resolver and the lookup are injectable
> (the tests never touch the network).
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass

ResolveFn = Callable[[str], str]  # host -> IP, raises on failure
LookupFn = Callable[[str], str]  # IP -> raw Cymru WHOIS text, raises on failure

_CYMRU_HOST = "whois.cymru.com"
_CYMRU_PORT = 43
_TIMEOUT = 10


@dataclass
class AsnResult:
    """One host's network origin, as announced in BGP."""

    host: str
    ip: str = ""
    asn: str = ""
    prefix: str = ""
    cc: str = ""
    registry: str = ""
    as_name: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.asn)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "ip": self.ip,
            "asn": self.asn,
            "prefix": self.prefix,
            "cc": self.cc,
            "registry": self.registry,
            "as_name": self.as_name,
            "error": self.error,
        }


def default_resolve(host: str) -> str:
    """Resolve a hostname to an IPv4 address (stdlib; no third party)."""
    return socket.gethostbyname(host)


def default_lookup(ip: str) -> str:
    """Query Team Cymru's WHOIS IP-to-ASN service for ``ip``.

    Opens a short-lived TCP connection to port 43 and sends a single verbose
    query. This is the layer's only outbound call to a non-target host.
    """
    query = f" -v {ip}\r\n".encode()
    with socket.create_connection((_CYMRU_HOST, _CYMRU_PORT), timeout=_TIMEOUT) as sock:
        sock.sendall(query)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def parse_cymru(text: str) -> dict[str, str]:
    """Parse the first data row of a Team Cymru verbose WHOIS response.

    The verbose format is a header row then pipe-delimited data:
    ``AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name``.
    Returns an empty dict when no data row is present.
    """
    for line in text.splitlines():
        if "|" not in line:
            continue
        cols = [c.strip() for c in line.split("|")]
        # a data row leads with the numeric AS; the header row ("AS | IP | …")
        # and any noise fail that test and are skipped
        if len(cols) < 7 or not cols[0].isdigit():
            continue
        return {
            "asn": cols[0],
            "ip": cols[1],
            "prefix": cols[2],
            "cc": cols[3],
            "registry": cols[4],
            "as_name": cols[6],
        }
    return {}


def asn_for(
    host: str,
    *,
    resolve: ResolveFn = default_resolve,
    lookup: LookupFn = default_lookup,
) -> AsnResult:
    """Resolve ``host`` and look up its ASN, never raising.

    Any failure (unresolvable name, WHOIS timeout, unparsable reply) is
    recorded on the result so one bad host cannot sink a batch.
    """
    try:
        ip = resolve(host)
    except Exception as exc:  # noqa: BLE001 — a resolution failure is data
        return AsnResult(host=host, error=f"resolve: {exc or type(exc).__name__}")
    try:
        raw = lookup(ip)
    except Exception as exc:  # noqa: BLE001 — a lookup failure is data
        return AsnResult(host=host, ip=ip, error=f"lookup: {exc or type(exc).__name__}")

    row = parse_cymru(raw)
    if not row:
        return AsnResult(host=host, ip=ip, error="no ASN in response")
    return AsnResult(
        host=host,
        ip=row.get("ip", ip),
        asn=row["asn"],
        prefix=row.get("prefix", ""),
        cc=row.get("cc", ""),
        registry=row.get("registry", ""),
        as_name=row.get("as_name", ""),
    )
