"""DSSE (Dead Simple Signing Envelope) encode/decode.

DSSE is the wrapper in-toto uses: a signature is computed over PAE(payloadType,
payload), not over the raw payload, so the payload type is bound into the signed
bytes. The signature covers these exact bytes and nothing else.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from .model import VCRError, _require

PAYLOAD_TYPE = "application/vnd.in-toto+json"


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
        try:
            payload = base64.standard_b64decode(d.get("payload", ""))
        except (ValueError, TypeError) as exc:
            raise VCRError(f"envelope.payload: not valid base64 ({exc})") from exc
        raw_sigs = d.get("signatures")
        _require(isinstance(raw_sigs, list) and raw_sigs, "envelope.signatures: non-empty list")
        sigs: list[Signature] = []
        for i, rs in enumerate(raw_sigs):
            _require(isinstance(rs, dict), f"signatures[{i}]: object")
            try:
                sig = base64.standard_b64decode(rs.get("sig", ""))
            except (ValueError, TypeError) as exc:
                raise VCRError(f"signatures[{i}].sig: not base64 ({exc})") from exc
            _require(bool(sig), f"signatures[{i}].sig: empty")
            keyid = rs.get("keyid")
            cert = rs.get("cert")
            sigs.append(
                Signature(
                    sig=sig,
                    keyid=keyid if isinstance(keyid, str) else None,
                    cert=cert if isinstance(cert, str) else None,
                )
            )
        return Envelope(payload=payload, payload_type=pt, signatures=sigs)
