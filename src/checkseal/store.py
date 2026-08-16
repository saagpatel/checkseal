"""The T0 store: durable, append-only check-results before they are sealed.

Architecture decision (see DESIGN.md): CheckSeal does NOT weld to Verification
Ledger. VL stores *coordination* records (payload/trust/actionable); a check
result is an *attestation fragment*. But the two align at the provenance-typing
layer, so this interface is deliberately shaped to be satisfiable by a VL
``LedgerAdapter``: a T0 record maps to a VL record with

    payload       = canonical JSON of one check result (subject + check entry)
    source_trust  = provenance.authority (operator | agent | ingested)
    durable       = keep past retention pruning

A JSONL store ships here; a VL-backed store is an optional extra post-skeleton,
where VL's retention (VL-4) and provenance typing (VL-1) earn their place for a
real fleet. Both satisfy ``SealStore``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .digest import canonical_bytes
from .model import Authority, CheckEntry, Subject, _require


@dataclass(frozen=True)
class CheckResult:
    """One check applied to one subject: the unit the store persists."""

    subject: Subject
    entry: CheckEntry

    def to_jsonable(self) -> dict[str, Any]:
        return {"subject": self.subject.to_jsonable(), "check_entry": self.entry.to_jsonable()}

    @staticmethod
    def from_jsonable(d: Any) -> "CheckResult":
        _require(isinstance(d, dict), "check result: must be an object")
        return CheckResult(
            subject=Subject.from_jsonable(d.get("subject")),
            entry=CheckEntry.from_jsonable(d.get("check_entry")),
        )


@dataclass(frozen=True)
class T0Record:
    id: int
    payload: str  # canonical JSON of a CheckResult
    source_trust: Authority
    durable: bool
    created_at: str

    def result(self) -> CheckResult:
        return CheckResult.from_jsonable(json.loads(self.payload))


@runtime_checkable
class SealStore(Protocol):
    def append(self, result: CheckResult, *, durable: bool = True) -> int: ...
    def read(self) -> list[T0Record]: ...


class JsonlSealStore(SealStore):
    """A single-file append-only JSONL store. stdlib only."""

    def __init__(self, path: str) -> None:
        self._path = path

    def append(self, result: CheckResult, *, durable: bool = True) -> int:
        rid = self._next_id()
        row = {
            "id": rid,
            "payload": canonical_bytes(result.to_jsonable()).decode("utf-8"),
            "source_trust": result.entry.provenance.authority.value,
            "durable": durable,
            "created_at": result.entry.runtime.ran_at,
        }
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        return rid

    def read(self) -> list[T0Record]:
        rows: list[T0Record] = []
        try:
            with open(self._path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    d: dict[str, Any] = json.loads(line)
                    rows.append(
                        T0Record(
                            id=int(d["id"]),
                            payload=str(d["payload"]),
                            source_trust=Authority(str(d["source_trust"])),
                            durable=bool(d["durable"]),
                            created_at=str(d["created_at"]),
                        )
                    )
        except FileNotFoundError:
            return []
        return rows

    def read_for_subject(self, subject_digest: str) -> list[CheckEntry]:
        """Every check entry whose subject digest matches (many checks / one subject)."""
        return [
            row.result().entry
            for row in self.read()
            if row.result().subject.digest == subject_digest
        ]

    def _next_id(self) -> int:
        rows = self.read()
        return (rows[-1].id + 1) if rows else 1
