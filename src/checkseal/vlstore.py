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
import json
from collections.abc import Iterator

from .digest import canonical_bytes
from .model import Authority, CheckEntry, VCRError
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

    def _iter_checkseal(self) -> Iterator[tuple[T0Record, CheckResult]]:
        """Yield ``(T0Record, CheckResult)`` for every well-formed CheckSeal record, id-ordered.

        A shared fleet ledger may also hold records written by other producers; those are
        skipped rather than crashing the read. ``created_at`` is taken from the check's own
        ``ran_at`` (as ``JsonlSealStore`` does), not the ledger's write time, so a result
        reads back identically whichever store persisted it. Ordering is by record id, since
        check order is part of the canonical statement bytes a signature covers.
        """
        ledger_cls, _trust_cls = _load_vl()
        with ledger_cls(self._db) as ledger:
            enveloped_records = list(ledger.read_all())
        for enveloped in sorted(enveloped_records, key=lambda e: int(e.record.id)):
            record = enveloped.record
            try:
                result = CheckResult.from_jsonable(json.loads(record.payload))
            except (ValueError, VCRError):
                continue  # not a CheckSeal check-result (foreign producer) - skip
            t0 = T0Record(
                id=int(record.id),
                payload=str(record.payload),
                source_trust=Authority(record.source_trust.value),
                durable=bool(record.durable),
                created_at=result.entry.runtime.ran_at,
            )
            yield t0, result

    def read(self) -> list[T0Record]:
        return [t0 for t0, _ in self._iter_checkseal()]

    def read_for_subject(self, subject_digest: str) -> list[CheckEntry]:
        """Every check entry whose subject digest matches (many checks / one subject)."""
        return [
            result.entry for _t0, result in self._iter_checkseal() if result.subject.digest == subject_digest
        ]
