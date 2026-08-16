"""Signing tiers and the signer/verifier abstraction.

Public N1 seals MUST be T2 (identity-bound keyless). T1 (local key) is a lower
tier for private use; T0 (unsigned) is a ledger row, never a public seal. The
sealer takes any Signer; the verifier takes any SignatureVerifier. Keeping this
an interface is what lets the T2 keyless backend and the T1 local backend share
one sealer and one verifier.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from enum import StrEnum

from ..dsse import Signature


class SigningTier(StrEnum):
    T0 = "T0"  # unsigned: ledger rows only, never a public seal
    T1 = "T1"  # local key: lower tier
    T2 = "T2"  # keyless identity-bound (Fulcio + Rekor): the only public tier


@dataclass(frozen=True)
class Identity:
    """Who a verified signature resolves to, and how strongly."""

    tier: SigningTier
    subject: str  # key id (T1) or OIDC identity (T2)
    issuer: str | None = None  # OIDC issuer for T2
    attested_authority: bool = False  # only T2 may claim operator/authority


class Signer(abc.ABC):
    @property
    @abc.abstractmethod
    def tier(self) -> SigningTier: ...

    @abc.abstractmethod
    def sign(self, data: bytes) -> Signature:
        """Sign the DSSE pre-authentication bytes."""


class SignatureVerifier(abc.ABC):
    @abc.abstractmethod
    def verify(self, data: bytes, sig: Signature) -> Identity:
        """Verify a signature over ``data`` and return the resolved identity.

        Must raise on any failure. Rekor freshness is checked separately by the
        seal verifier (contract step 2), not here.
        """
