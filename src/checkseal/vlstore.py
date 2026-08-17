"""VL-backed ``SealStore`` (optional extra: ``pip install 'checkseal[vl]'``).

Stores CheckSeal T0 check-results in a Verification Ledger so a real fleet gets the
ledger's retention (VL-4) and provenance typing (VL-1). One check result maps to one
ledger record: a canonical-JSON payload with ``source_trust`` set from the check's
provenance authority. This is the seam documented in ``store.py``; CheckSeal core never
imports it, so the ``verification-ledger`` dependency stays optional. The import is
resolved lazily inside methods, so ``import checkseal.vlstore`` succeeds without the
extra and only *using* the store raises a helpful error.
"""

from __future__ import annotations

import importlib

from .digest import canonical_bytes
from .model import Authority, CheckEntry
from .store import CheckResult, SealStore, T0Record


def _load_vl() -> tuple:
    # importlib keeps the optional dependency invisible to static analysis: the module
    # type-checks and imports without the extra; only *using* the store needs VL.
    try:
        ledger_mod = importlib.import_module("verification_ledger.ledger")
        model_mod = importlib.import_module("verification_ledger.model")
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "VerificationLedgerSealStore requires the 'vl' extra: pip install 'checkseal[vl]'"
        ) from exc
    return ledger_mod.Ledger, model_mod.Trust


class VerificationLedgerSealStore(SealStore):
    """A ``SealStore`` backed by a Verification Ledger database file."""

    def __init__(self, db_path: str) -> None:
        self._db = db_path

    def append(self, result: CheckResult, *, durable: bool = True) -> int:
        ledger_cls, trust_cls = _load_vl()
        with ledger_cls(self._db) as ledger:
            written = ledger.write(
                canonical_bytes(result.to_jsonable()).decode("utf-8"),
                source_trust=trust_cls(result.entry.provenance.authority.value),
                durable=durable,
            )
            return int(written.record_id)

    def read(self) -> list[T0Record]:
        ledger_cls, _trust_cls = _load_vl()
        with ledger_cls(self._db) as ledger:
            return [
                T0Record(
                    id=int(enveloped.record.id),
                    payload=str(enveloped.record.payload),
                    source_trust=Authority(enveloped.record.source_trust.value),
                    durable=bool(enveloped.record.durable),
                    created_at=str(enveloped.record.created_at),
                )
                for enveloped in ledger.read_all()
            ]

    def read_for_subject(self, subject_digest: str) -> list[CheckEntry]:
        """Every check entry whose subject digest matches (many checks / one subject)."""
        return [
            record.result().entry
            for record in self.read()
            if record.result().subject.digest == subject_digest
        ]
