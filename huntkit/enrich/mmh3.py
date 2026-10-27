"""MurmurHash3 (x86, 32-bit) — a self-contained, pure-Python port.

Shodan indexes a site's favicon by ``mmh3.hash(base64(favicon_bytes))``, so a
favicon hash is the pivot that turns one asset into *every* host serving the
same icon. The reference hasher ships as a C extension (``mmh3``); HuntKit
keeps its runtime dependencies to three pure-Python packages, so rather than
pull a compiled wheel onto a hunter's box we port the ~40-line algorithm here.

This is a faithful port of Austin Appleby's ``MurmurHash3_x86_32`` (public
domain). It returns a *signed* 32-bit int by default, matching the ``mmh3``
package — which is the exact value Shodan's ``http.favicon.hash:`` expects.
"""

from __future__ import annotations

_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_MASK = 0xFFFFFFFF


def _rotl32(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & _MASK


def hash_bytes(data: bytes, seed: int = 0, *, signed: bool = True) -> int:
    """MurmurHash3_x86_32 of ``data``.

    ``signed`` (the default) folds the result into the signed 32-bit range,
    so it equals ``mmh3.hash(data, seed)`` from the C package.
    """
    length = len(data)
    nblocks = length // 4
    h1 = seed & _MASK

    # body — four bytes at a time, little-endian
    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4 : i * 4 + 4], "little")
        k1 = (k1 * _C1) & _MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & _MASK

    # tail — the trailing 0..3 bytes
    tail = data[nblocks * 4 :]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * _C1) & _MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK
        h1 ^= k1

    # finalisation mix (fmix32)
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & _MASK
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & _MASK
    h1 ^= h1 >> 16

    if signed and h1 & 0x80000000:
        return h1 - 0x100000000
    return h1
