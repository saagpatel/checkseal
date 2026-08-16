"""Canonical serialization and digests.

The signature covers exact bytes, so serialization must be deterministic:
sorted keys, no insignificant whitespace, UTF-8, no ASCII escaping of
non-ASCII. This is the one place bytes are minted; everyone else calls here.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding used for digests and DSSE payloads."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, *, chunk: int = 1 << 20) -> str:
    """Stream a file through sha256 without loading it whole."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def digest_of(obj: Any) -> str:
    """sha256 of the canonical encoding of a JSON-able object."""
    return sha256_hex(canonical_bytes(obj))
