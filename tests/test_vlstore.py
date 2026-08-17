"""The VL-backed SealStore round-trips check-results faithfully through a real ledger.

Skips cleanly when the optional ``vl`` extra (verification-ledger) is not installed.
"""

import json

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
from checkseal.store import CheckResult, JsonlSealStore, SealStore  # noqa: E402
from checkseal.vlstore import VerificationLedgerSealStore  # noqa: E402


def _result(
    digest: str,
    *,
    authority: Authority = Authority.AGENT,
    ran_at: str = "2026-08-16T00:00:00Z",
) -> CheckResult:
    subject = Subject(
        kind=SubjectKind.HARNESS_CONFIG.value, digest=digest, name="x", media_type="application/json"
    )
    entry = CheckEntry(
        check=Check(id="guard/x/destructive-execution", kind=CheckKind.GUARD, version="1", config_ref=digest),
        verdict=Verdict(result=Result.PASS, enforced=Enforced.OBSERVED),
        evidence=Evidence(kind=EvidenceKind.LOG_DIGEST, grade=Grade.B, digest="00" * 32),
        runtime=Runtime(ran_at=ran_at, runner=Runner.CI),
        provenance=Provenance(authority=authority),
    )
    return CheckResult(subject=subject, entry=entry)


def test_satisfies_sealstore_protocol():
    assert isinstance(VerificationLedgerSealStore(":memory:"), SealStore)


def test_payload_byte_identical_to_jsonl_store(tmp_path):
    # The core contract: a CheckResult sealed via VL must reconstruct the SAME predicate
    # as the reference JSONL store, i.e. byte-identical canonical payloads.
    result = _result("aa" * 32)
    vl = VerificationLedgerSealStore(str(tmp_path / "vl.db"))
    vl.append(result)
    jsonl = JsonlSealStore(str(tmp_path / "store.jsonl"))
    jsonl.append(result)
    assert vl.read()[0].payload == jsonl.read()[0].payload


def test_created_at_is_ran_at_not_ledger_write_time(tmp_path):
    vl = VerificationLedgerSealStore(str(tmp_path / "vl.db"))
    vl.append(_result("aa" * 32, ran_at="2020-01-02T03:04:05Z"))
    assert vl.read()[0].created_at == "2020-01-02T03:04:05Z"


def test_agent_trust_roundtrips(tmp_path):
    vl = VerificationLedgerSealStore(str(tmp_path / "vl.db"))
    vl.append(_result("aa" * 32, authority=Authority.AGENT))
    assert vl.read()[0].source_trust is Authority.AGENT


def test_operator_clamped_to_agent_but_payload_preserved(tmp_path):
    # VL-1: an in-band writer cannot mint operator trust, so the record-level trust
    # clamps to agent. The sealed predicate still carries the payload's own provenance
    # (operator), unchanged, because the seal is built from the payload.
    vl = VerificationLedgerSealStore(str(tmp_path / "op.db"))
    vl.append(_result("aa" * 32, authority=Authority.OPERATOR))
    row = vl.read()[0]
    assert row.source_trust is Authority.AGENT
    assert row.result().entry.provenance.authority is Authority.OPERATOR


def test_multiple_checks_one_subject_are_id_ordered(tmp_path):
    vl = VerificationLedgerSealStore(str(tmp_path / "vl.db"))
    for i in range(3):
        vl.append(_result("aa" * 32, ran_at=f"2026-08-16T00:00:0{i}Z"))
    entries = vl.read_for_subject("aa" * 32)
    assert [e.runtime.ran_at for e in entries] == [
        "2026-08-16T00:00:00Z",
        "2026-08-16T00:00:01Z",
        "2026-08-16T00:00:02Z",
    ]
    assert vl.read_for_subject("bb" * 32) == []


def test_durable_false_roundtrips(tmp_path):
    vl = VerificationLedgerSealStore(str(tmp_path / "vl.db"))
    vl.append(_result("aa" * 32), durable=False)
    assert vl.read()[0].durable is False


def test_skips_foreign_records_on_a_shared_ledger(tmp_path):
    # A shared fleet ledger may hold records written by other producers; read() must
    # skip them, not crash, and surface only CheckSeal check-results.
    from verification_ledger.ledger import Ledger
    from verification_ledger.model import Trust

    db = str(tmp_path / "shared.db")
    with Ledger(db) as ledger:
        ledger.write(json.dumps({"not": "a check result"}), source_trust=Trust.AGENT, durable=True)
    vl = VerificationLedgerSealStore(db)
    vl.append(_result("aa" * 32))

    rows = vl.read()
    assert len(rows) == 1
    assert rows[0].result().subject.digest == "aa" * 32
    assert len(vl.read_for_subject("aa" * 32)) == 1
