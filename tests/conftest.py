from __future__ import annotations

import json

import pytest

from checkseal.digest import sha256_hex
from checkseal.model import (
    Authority,
    Check,
    CheckEntry,
    CheckKind,
    Enforced,
    EnforcedProof,
    Evidence,
    EvidenceKind,
    Grade,
    Provenance,
    Result,
    Runner,
    Runtime,
    Subject,
    SubjectKind,
)

VALID_SHA = sha256_hex(b"config")
RAN_AT = "2026-08-16T00:00:00Z"


def make_entry(
    *,
    check_id: str = "guard/destructive-execution",
    kind: CheckKind = CheckKind.GUARD,
    enforced: Enforced = Enforced.ENFORCED,
    grade: Grade = Grade.A,
    result: Result = Result.PASS,
    evidence_kind: EvidenceKind = EvidenceKind.EXIT_CODE,
    config_ref: str | None = VALID_SHA,
    proof: EnforcedProof | None = None,
    authority: Authority = Authority.OPERATOR,
) -> CheckEntry:
    return CheckEntry(
        check=Check(id=check_id, kind=kind, version="1", config_ref=config_ref),
        verdict=Verdict_(result, enforced, proof),
        evidence=Evidence(kind=evidence_kind, grade=grade, digest=sha256_hex(b"evidence")),
        runtime=Runtime(ran_at=RAN_AT, runner=Runner.CI, env_digest=sha256_hex(b"env")),
        provenance=Provenance(authority=authority),
    )


def Verdict_(result, enforced, proof):
    from checkseal.model import Verdict

    return Verdict(result=result, enforced=enforced, enforced_proof=proof)


def make_subject(content: bytes = b"the essay body", name: str = "essay/stranded") -> Subject:
    return Subject(kind=SubjectKind.ARTIFACT.value, digest=sha256_hex(content), name=name)


def write_hb_report(
    path,
    *,
    corpus: str = "asi05-destructive-execution",
    enforced: int = 46,
    advised: int = 0,
    threat_class: str | None = None,
) -> EnforcedProof:
    """Write a HarnessBench-report/v1 fixture and return an EnforcedProof for it."""
    report = {
        "schema": "harnessbench-report/v1",
        "subject": "semantic-clean-room",
        "harness": "claude-code",
        "corpus": corpus,
        "corpus_version": "1",
        "ees": 1.0 if advised == 0 else 0.5,
        "verdicts": {"enforced": enforced, "advised": advised, "permitted": 22, "errors": 0},
        "n": 68,
    }
    if threat_class is not None:
        report["threat_class"] = threat_class
    raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(raw)
    return EnforcedProof(sha256=sha256_hex(raw), uri=str(path))


@pytest.fixture
def local_signer():
    from checkseal.sign.local import LocalKeySigner

    return LocalKeySigner.generate()
