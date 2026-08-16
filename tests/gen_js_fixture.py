"""Emit a JSON fixture for the JS verifier test: a real Python-signed T1 seal,
the artifact bytes, and the raw Ed25519 public key. Proves the seal format is
language-agnostic (Python signs, JavaScript verifies the same bytes).

Usage: PYTHONPATH=src python3 tests/gen_js_fixture.py  ->  JSON on stdout
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization

from checkseal.digest import sha256_hex
from checkseal.model import (
    Authority,
    Check,
    CheckEntry,
    CheckKind,
    Enforced,
    Evidence,
    EvidenceKind,
    Grade,
    Predicate,
    Provenance,
    Result,
    Runner,
    Runtime,
    Subject,
)
from checkseal.seal import sign_local
from checkseal.sign.local import LocalKeySigner


def _raw_pub_b64(signer: LocalKeySigner) -> str:
    raw = signer.public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.standard_b64encode(raw).decode("ascii")


def main() -> None:
    artifact = b"js cross-language artifact"
    subject = Subject(kind="artifact", digest=sha256_hex(artifact), name="essay/stranded")
    entry = CheckEntry(
        check=Check(id="review/rights-gate", kind=CheckKind.REVIEW, version="1"),
        verdict=Verdict_pass(),
        evidence=Evidence(kind=EvidenceKind.TRANSCRIPT_DIGEST, grade=Grade.B, digest=sha256_hex(b"ev")),
        runtime=Runtime(ran_at="2026-08-16T00:00:00Z", runner=Runner.HUMAN),
        provenance=Provenance(authority=Authority.OPERATOR),
    )
    predicate = Predicate(subject=subject, checks=[entry])

    signer = LocalKeySigner.generate()
    seal = sign_local(predicate, signer, public=False)
    other = LocalKeySigner.generate()

    print(
        json.dumps(
            {
                "envelope": seal.envelope.to_jsonable(),
                "artifact_b64": base64.standard_b64encode(artifact).decode("ascii"),
                "pubkey_raw_b64": _raw_pub_b64(signer),
                "wrong_pubkey_raw_b64": _raw_pub_b64(other),
            }
        )
    )


def Verdict_pass():
    from checkseal.model import Verdict

    return Verdict(result=Result.PASS, enforced=Enforced.ADVISORY)


if __name__ == "__main__":
    main()
