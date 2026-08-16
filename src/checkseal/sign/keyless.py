"""T2 keyless signing: Sigstore (Fulcio short-lived cert + Rekor log).

This is the ONLY tier valid for a public N1 seal. It binds a signature to an
OIDC identity via a ~10-minute Fulcio certificate and records the signature in
the Rekor transparency log; the Rekor inclusion timestamp is what proves the
seal was signed while the cert was valid (a not-after bound). Rekor does NOT
prove not-before; that honest limit is documented in the Verifier Contract.

Requires the ``keyless`` extra (``sigstore``). Keyless signing needs an OIDC
credential and network, so it is exercised in CI, not on a dev box without an
ambient token. Implemented against sigstore-python; the pin lives in
pyproject.toml. Structurally parallel to HarnessBench's live tier: built and
reviewed, exercised only where its preconditions hold.
"""

from __future__ import annotations

import json
from typing import Any

from ..model import VCRError
from .base import Identity, SigningTier

_SIGSTORE_HINT = "T2 keyless signing needs 'sigstore' (install checkseal[keyless])"


def _import_sigstore() -> Any:
    try:
        import sigstore  # noqa: F401

        return sigstore
    except ModuleNotFoundError as exc:  # pragma: no cover - env without the extra
        raise VCRError(_SIGSTORE_HINT) from exc


def sign_statement_keyless(statement: dict[str, Any], *, identity_token: str | None = None) -> str:
    """Sign an in-toto Statement keyless and return a Sigstore bundle (JSON str).

    The bundle's enclosed DSSE payload is the in-toto Statement, so a T2 seal
    covers the same bytes a T1 ``.intoto.jsonl`` would. The bundle also carries
    the Fulcio cert and the Rekor inclusion proof as verification material.
    """
    _import_sigstore()
    from sigstore.models import Bundle  # noqa: F401
    from sigstore.oidc import IdentityToken, Issuer, detect_credential
    from sigstore.sign import SigningContext

    raw_token = identity_token or detect_credential()
    if raw_token is None:  # pragma: no cover - CI/OIDC only
        raise VCRError("no ambient OIDC credential; pass identity_token or run in an OIDC context")
    token = raw_token if isinstance(raw_token, IdentityToken) else IdentityToken(raw_token)

    ctx = SigningContext.production()
    from sigstore.dsse import Statement, _StatementBuilder  # noqa: F401

    # sigstore's Statement wraps the same fields; hand it our canonical dict.
    stmt = Statement(json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    with ctx.signer(token) as signer:
        bundle = signer.sign_dsse(stmt)
    return bundle.to_json()


def verify_bundle_keyless(
    bundle_json: str,
    *,
    expected_identity: str,
    expected_issuer: str,
) -> tuple[bytes, Identity]:
    """Verify a Sigstore bundle and return (statement_bytes, Identity).

    Confirms the signature, the Fulcio cert chains to the Sigstore trust root,
    the Rekor inclusion proof, and that the OIDC identity/issuer match policy.
    T2 is the only tier permitted to report ``attested_authority``.
    """
    _import_sigstore()
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify.policy import Identity as IdentityPolicy

    bundle = Bundle.from_json(bundle_json)
    verifier = Verifier.production()
    policy = IdentityPolicy(identity=expected_identity, issuer=expected_issuer)
    payload_type, payload = verifier.verify_dsse(bundle, policy)
    if payload_type != "application/vnd.in-toto+json":
        raise VCRError(f"unexpected DSSE payloadType from bundle: {payload_type!r}")
    identity = Identity(
        tier=SigningTier.T2,
        subject=expected_identity,
        issuer=expected_issuer,
        attested_authority=True,
    )
    return payload, identity
