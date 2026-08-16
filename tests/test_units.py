from __future__ import annotations

import pytest
from conftest import make_entry, make_subject

from checkseal.digest import canonical_bytes, digest_of
from checkseal.dsse import PAYLOAD_TYPE, Envelope, Signature, pae
from checkseal.model import (
    Authority,
    Enforced,
    Evidence,
    EvidenceKind,
    Grade,
    Predicate,
    Result,
    VCRError,
)
from checkseal.profile import validate_n1_profile
from checkseal.statement import build_statement, parse_statement, statement_bytes
from checkseal.trust import check_invariant_e1, render_trust_floor, trust_floor


def test_canonical_bytes_are_deterministic():
    a = canonical_bytes({"b": 1, "a": [3, 2]})
    b = canonical_bytes({"a": [3, 2], "b": 1})
    assert a == b == b'{"a":[3,2],"b":1}'


def test_digest_stable():
    assert digest_of({"x": 1}) == digest_of({"x": 1})


def test_trust_floor_is_the_weaker_axis():
    # enforced (2) + grade C (0) -> floor 0, never displays bare "enforced".
    e = make_entry(enforced=Enforced.ENFORCED, grade=Grade.A)
    assert trust_floor(make_entry(enforced=Enforced.ADVISORY, grade=Grade.A)) == 1
    assert trust_floor(e) == 2
    weak = make_entry(enforced=Enforced.OBSERVED, grade=Grade.A)
    assert trust_floor(weak) == 0
    assert render_trust_floor(weak) == "telemetry only"


def test_e1_rejects_enforced_with_human_only_evidence():
    bad = make_entry(enforced=Enforced.ENFORCED, grade=Grade.C, config_ref=None)
    with pytest.raises(VCRError):
        check_invariant_e1(bad)


def test_e1_allows_enforced_grade_b_with_config_ref():
    ok = make_entry(enforced=Enforced.ENFORCED, grade=Grade.B)  # config_ref set by default
    check_invariant_e1(ok)  # no raise


def test_predicate_round_trip():
    pred = Predicate(subject=make_subject(), checks=[make_entry()])
    again = Predicate.from_jsonable(pred.to_jsonable())
    assert again.subject.digest == pred.subject.digest
    assert again.checks[0].check.id == "guard/destructive-execution"


def test_evidence_inline_is_forbidden():
    with pytest.raises(VCRError, match="inline"):
        Evidence.from_jsonable(
            {"kind": "exit-code", "grade": "A", "digest": {"sha256": "0" * 64}, "inline": "x"}
        )


def test_bad_check_id_rejected():
    from checkseal.model import Check

    with pytest.raises(VCRError):
        Check.from_jsonable({"id": "Bad Id", "kind": "guard", "version": "1"})


def test_bad_sha_rejected():
    with pytest.raises(VCRError):
        Evidence.from_jsonable({"kind": "exit-code", "grade": "A", "digest": {"sha256": "nope"}})


def test_statement_subject_predicate_coupling():
    pred = Predicate(subject=make_subject(), checks=[make_entry()])
    stmt = build_statement(pred)
    # tamper: statement subject digest disagrees with the predicate subject
    stmt["subject"][0]["digest"]["sha256"] = "f" * 64
    with pytest.raises(VCRError, match="does not match"):
        parse_statement(stmt)


def test_dsse_pae_and_envelope_round_trip():
    payload = statement_bytes(Predicate(subject=make_subject(), checks=[make_entry()]))
    env = Envelope(payload=payload, payload_type=PAYLOAD_TYPE, signatures=[Signature(sig=b"xx", keyid="k")])
    back = Envelope.from_jsonable(env.to_jsonable())
    assert back.payload == payload
    assert back.signatures[0].sig == b"xx"
    assert env.signing_bytes() == pae(PAYLOAD_TYPE, payload)


def test_profile_public_enforced_needs_proof():
    pred = Predicate(subject=make_subject(), checks=[make_entry(proof=None)])
    validate_n1_profile(pred, public=False)  # private ok
    with pytest.raises(VCRError, match="enforced_proof"):
        validate_n1_profile(pred, public=True)


def test_profile_grade_c_needs_operator():
    entry = make_entry(
        enforced=Enforced.ADVISORY,
        grade=Grade.C,
        evidence_kind=EvidenceKind.REVIEWER_ID,
        authority=Authority.AGENT,
        result=Result.PASS,
    )
    pred = Predicate(subject=make_subject(), checks=[entry])
    with pytest.raises(VCRError, match="grade C"):
        validate_n1_profile(pred, public=False)
