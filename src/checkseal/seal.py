"""The sealer: group T0 check-results into a predicate, validate, sign, emit.

Per-bundle signing (one signature over one subject's checks), per the frozen N1
profile. Because each check carries its own evidence digest, a stale digest
fails only that check at verify time; it never invalidates the signature or the
other checks. The signature attests the claim as made; the verifier computes
current truth per check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .dsse import PAYLOAD_TYPE, Envelope
from .model import Predicate, Subject, VCRError
from .profile import validate_n1_profile
from .sign.base import Signer, SigningTier
from .statement import build_statement, statement_bytes
from .store import JsonlSealStore


def assemble(store: JsonlSealStore, subject: Subject) -> Predicate:
    """Collect every stored check for a subject into one predicate."""
    entries = store.read_for_subject(subject.digest)
    if not entries:
        raise VCRError(f"no stored check-results for subject digest {subject.digest[:12]}...")
    return Predicate(subject=subject, checks=entries)


@dataclass(frozen=True)
class Seal:
    """A signed seal, in one of two on-disk forms."""

    tier: SigningTier
    statement: dict[str, Any]
    envelope: Envelope | None = None  # T0/T1 -> .intoto.jsonl
    bundle_json: str | None = None  # T2 -> .sigstore.json

    def to_intoto_jsonl(self) -> str:
        if self.envelope is None:
            raise VCRError("this seal has no DSSE envelope (T2 seals are Sigstore bundles)")
        import json

        return json.dumps(self.envelope.to_jsonable(), sort_keys=True, separators=(",", ":"))


def sign_local(predicate: Predicate, signer: Signer, *, public: bool = False) -> Seal:
    """Sign with a local (T1) or unsigned-marker signer. Not valid for public N1."""
    validate_n1_profile(predicate, public=public)
    if public and signer.tier is not SigningTier.T2:
        raise VCRError(
            f"public N1 seals must be T2 keyless; refusing to sign public seal at tier {signer.tier.value}"
        )
    payload = statement_bytes(predicate)
    envelope = Envelope(
        payload=payload,
        payload_type=PAYLOAD_TYPE,
        signatures=[signer.sign(_pae(payload))],
    )
    return Seal(tier=signer.tier, statement=build_statement(predicate), envelope=envelope)


def sign_keyless(predicate: Predicate, *, identity_token: str | None = None) -> Seal:
    """Sign a public seal with T2 Sigstore keyless. Requires the keyless extra."""
    validate_n1_profile(predicate, public=True)
    from .sign.keyless import sign_statement_keyless

    statement = build_statement(predicate)
    bundle_json = sign_statement_keyless(statement, identity_token=identity_token)
    return Seal(tier=SigningTier.T2, statement=statement, bundle_json=bundle_json)


def _pae(payload: bytes) -> bytes:
    from .dsse import pae

    return pae(PAYLOAD_TYPE, payload)
