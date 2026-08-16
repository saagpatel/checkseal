"""T1 local-key signing with Ed25519.

Fully offline and reproducible: used for tests and private seals. NOT valid for
public N1 seals, which must be T2. Requires the ``cryptography`` extra.
"""

from __future__ import annotations

from ..digest import sha256_hex
from ..dsse import Signature
from ..model import VCRError
from .base import Identity, SignatureVerifier, Signer, SigningTier

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _HAVE_CRYPTO = True
except ModuleNotFoundError:  # pragma: no cover - exercised via the [sign] extra
    _HAVE_CRYPTO = False


def _require_crypto() -> None:
    if not _HAVE_CRYPTO:
        raise VCRError("T1 signing needs the 'cryptography' package (install checkseal[sign])")


def _keyid(public: "Ed25519PublicKey") -> str:
    from cryptography.hazmat.primitives import serialization

    raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "ed25519:" + sha256_hex(raw)[:16]


class LocalKeySigner(Signer):
    def __init__(self, private_key: "Ed25519PrivateKey") -> None:
        _require_crypto()
        self._key = private_key
        self._keyid = _keyid(private_key.public_key())

    @property
    def tier(self) -> SigningTier:
        return SigningTier.T1

    @property
    def keyid(self) -> str:
        return self._keyid

    @property
    def public_key(self) -> "Ed25519PublicKey":
        return self._key.public_key()

    def verifier(self) -> "LocalKeyVerifier":
        """The matching verifier for this signer (avoids private-key reach-through)."""
        return LocalKeyVerifier(self._key.public_key())

    def sign(self, data: bytes) -> Signature:
        return Signature(sig=self._key.sign(data), keyid=self._keyid)

    @staticmethod
    def generate() -> "LocalKeySigner":
        _require_crypto()
        return LocalKeySigner(Ed25519PrivateKey.generate())


class LocalKeyVerifier(SignatureVerifier):
    def __init__(self, public_key: "Ed25519PublicKey") -> None:
        _require_crypto()
        self._key = public_key
        self._keyid = _keyid(public_key)

    def verify(self, data: bytes, sig: Signature) -> Identity:
        if sig.keyid is not None and sig.keyid != self._keyid:
            raise VCRError(f"key id mismatch: envelope {sig.keyid!r} != verifier {self._keyid!r}")
        try:
            self._key.verify(sig.sig, data)
        except InvalidSignature as exc:
            raise VCRError("Ed25519 signature verification failed") from exc
        return Identity(tier=SigningTier.T1, subject=self._keyid, attested_authority=False)


def write_private_pem(signer: LocalKeySigner, path: str) -> None:
    from cryptography.hazmat.primitives import serialization

    pem = signer._key.private_bytes(  # noqa: SLF001 - key IO helper
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as fh:
        fh.write(pem)


def load_private_signer(path: str) -> LocalKeySigner:
    _require_crypto()
    from cryptography.hazmat.primitives import serialization

    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise VCRError("key file is not an Ed25519 private key")
    return LocalKeySigner(key)


def write_public_pem(signer: LocalKeySigner, path: str) -> None:
    from cryptography.hazmat.primitives import serialization

    pem = signer._key.public_key().public_bytes(  # noqa: SLF001 - key IO helper
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as fh:
        fh.write(pem)


def load_public_verifier(path: str) -> LocalKeyVerifier:
    _require_crypto()
    from cryptography.hazmat.primitives import serialization

    with open(path, "rb") as fh:
        key = serialization.load_pem_public_key(fh.read())
    if not isinstance(key, Ed25519PublicKey):
        raise VCRError("key file is not an Ed25519 public key")
    return LocalKeyVerifier(key)
