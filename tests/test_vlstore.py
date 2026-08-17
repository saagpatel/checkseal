"""The VL-backed SealStore round-trips check-results through a real ledger.

Skips cleanly when the optional ``vl`` extra (verification-ledger) is not installed.
"""

import pytest

pytest.importorskip("verification_ledger")

from checkseal.model import (  # noqa: E402
    Authority,
    Check,
    CheckEntry,
    CheckKind,
    Enforced,
    Evidence,
    EvidenceKind,
    Grade,
    Provenance,
    Result,
    Runner,
    Runtime,
    Subject,
    SubjectKind,
    Verdict,
)
from checkseal.store import CheckResult  # noqa: E402
from checkseal.vlstore import VerificationLedgerSealStore  # noqa: E402


def _result(digest: str) -> CheckResult:
    subject = Subject(
        kind=SubjectKind.HARNESS_CONFIG.value, digest=digest, name="x", media_type="application/json"
    )
    entry = CheckEntry(
        check=Check(id="guard/x/destructive-execution", kind=CheckKind.GUARD, version="1", config_ref=digest),
        verdict=Verdict(result=Result.PASS, enforced=Enforced.OBSERVED),
        evidence=Evidence(kind=EvidenceKind.LOG_DIGEST, grade=Grade.B, digest="00" * 32),
        runtime=Runtime(ran_at="2026-08-16T00:00:00Z", runner=Runner.CI),
        provenance=Provenance(authority=Authority.AGENT),
    )
    return CheckResult(subject=subject, entry=entry)


def test_roundtrip_and_read_for_subject(tmp_path):
    store = VerificationLedgerSealStore(str(tmp_path / "vl.db"))

    rid = store.append(_result("aa" * 32))
    assert rid >= 1

    rows = store.read()
    assert len(rows) == 1
    assert rows[0].result().subject.digest == "aa" * 32
    assert rows[0].source_trust is Authority.AGENT

    entries = store.read_for_subject("aa" * 32)
    assert len(entries) == 1
    assert entries[0].check.config_ref == "aa" * 32
    assert store.read_for_subject("bb" * 32) == []


def test_satisfies_sealstore_protocol():
    from checkseal.store import SealStore

    assert isinstance(VerificationLedgerSealStore(":memory:"), SealStore)
