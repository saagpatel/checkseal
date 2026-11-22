"""DSSE (Dead Simple Signing Envelope) encode/decode.

DSSE is the wrapper in-toto uses: a signature is computed over PAE(payloadType,
payload), not over the raw payload, so the payload type is bound into the signed
bytes. The signature covers these exact bytes and nothing else.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any

from .model import VCRError, _require

PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Canonical standard base64 (RFC 4648 section 4) with mandatory "=" padding. The
# JavaScript verifier uses the same pattern plus the same round-trip check.
_CANONICAL_B64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def b64decode_canonical(value: Any, ctx: str) -> bytes:
    """Decode canonical padded standard base64, refusing every other spelling.

    Refused: non-string values, whitespace, URL-safe or other non-alphabet
    characters, missing or excess padding, and non-zero trailing bits. So every
    byte string has exactly one accepted encoding, in Python and in JavaScript.
    """
    _require(isinstance(value, str), f"{ctx}: must be a base64 string")
    assert isinstance(value, str)
    _require(_CANONICAL_B64.fullmatch(value) is not None, f"{ctx}: not canonical padded base64")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - the pattern already excludes these
        raise VCRError(f"{ctx}: not valid base64 ({exc})") from exc
    _require(base64.standard_b64encode(data).decode("ascii") == value, f"{ctx}: non-canonical base64")
    return data


def pae(payload_type: str, payload: bytes) -> bytes:
    """Pre-Authentication Encoding, per the DSSE spec."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(t), t, len(payload), payload)


@dataclass(frozen=True)
class Signature:
    sig: bytes
    keyid: str | None = None
    cert: str | None = None  # PEM Fulcio cert for T2 keyless


@dataclass(frozen=True)
class Envelope:
    payload: bytes
    payload_type: str
    signatures: list[Signature]

    def signing_bytes(self) -> bytes:
        return pae(self.payload_type, self.payload)

    def to_jsonable(self) -> dict[str, Any]:
        sigs: list[dict[str, Any]] = []
        for s in self.signatures:
            entry: dict[str, Any] = {"sig": base64.standard_b64encode(s.sig).decode("ascii")}
            if s.keyid is not None:
                entry["keyid"] = s.keyid
            if s.cert is not None:
                entry["cert"] = s.cert
            sigs.append(entry)
        return {
            "payload": base64.standard_b64encode(self.payload).decode("ascii"),
            "payloadType": self.payload_type,
            "signatures": sigs,
        }

    @staticmethod
    def from_jsonable(d: Any) -> Envelope:
        _require(isinstance(d, dict), "envelope: must be an object")
        pt = d.get("payloadType")
        _require(isinstance(pt, str), "envelope.payloadType: string")
        payload = b64decode_canonical(d.get("payload"), "envelope.payload")
        raw_sigs = d.get("signatures")
        _require(isinstance(raw_sigs, list) and len(raw_sigs) > 0, "envelope.signatures: non-empty list")
        sigs: list[Signature] = []
        for i, rs in enumerate(raw_sigs):
            _require(isinstance(rs, dict), f"signatures[{i}]: object")
            sig = b64decode_canonical(rs.get("sig"), f"signatures[{i}].sig")
            _require(bool(sig), f"signatures[{i}].sig: empty")
            keyid = rs.get("keyid")
            cert = rs.get("cert")
            _require(keyid is None or isinstance(keyid, str), f"signatures[{i}].keyid: must be a string")
            _require(cert is None or isinstance(cert, str), f"signatures[{i}].cert: must be a string")
            sigs.append(Signature(sig=sig, keyid=keyid, cert=cert))
        return Envelope(payload=payload, payload_type=pt, signatures=sigs)
