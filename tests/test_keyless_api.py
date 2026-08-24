"""Guard the sigstore API surface the T2 keyless path depends on.

The keyless seal is exercised only in CI (it needs an OIDC credential), so a
sigstore API rename slips past the unit suite and fails at a live seal run -
which is exactly how `_StatementBuilder` -> `StatementBuilder` (sigstore 3.x)
broke the first public-seal workflow. This test pins every sigstore symbol
`checkseal.sign.keyless` imports, plus the `Statement(bytes)` constructor it
relies on, so the next drift fails here instead. Skips cleanly without the
`keyless` extra installed.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("sigstore")


def test_sign_path_symbols_exist():
    # The exact imports at the top of sign_statement_keyless (sigstore 4.x).
    from sigstore.dsse import Statement  # noqa: F401
    from sigstore.oidc import IdentityToken, detect_credential  # noqa: F401
    from sigstore.sign import ClientTrustConfig, SigningContext

    # 4.x replaced SigningContext.production() with an explicit trust config;
    # pin the exact construction the keyless path uses so a further rename fails
    # here, not at a live seal run.
    assert hasattr(SigningContext, "from_trust_config")
    assert hasattr(ClientTrustConfig, "production")


def test_verify_path_symbols_exist():
    # The exact imports at the top of verify_bundle_keyless.
    from sigstore.models import Bundle  # noqa: F401
    from sigstore.verify import Verifier  # noqa: F401
    from sigstore.verify.policy import Identity  # noqa: F401


def test_statement_accepts_raw_intoto_bytes():
    # sign_statement_keyless hands sigstore a canonical in-toto Statement as raw
    # bytes; if that constructor contract changes, keyless signing breaks.
    from sigstore.dsse import Statement

    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "x", "digest": {"sha256": "a" * 64}}],
        "predicateType": "https://saagarpatel.dev/vcr/v0.2",
        "predicate": {"vcr_version": "0.2"},
    }
    raw = json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert Statement(raw) is not None
