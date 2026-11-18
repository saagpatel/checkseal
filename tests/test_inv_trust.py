"""Trust-policy invariants (INV-P*): trust floor, E1, the N1 profile, the
verifier's per-entry decision table, proof binding, and freshness.

The enum-valued policies have finite domains, so several tests enumerate the
whole product: for those dimensions the property is proven by exhaustion.
"""

from __future__ import annotations

import itertools
import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from _invariant_support import SIGNER, SealCase, seal_cases, sha_hex
from checkseal.digest import sha256_hex
from checkseal.hbresolve import EES_FLOOR, resolve_enforced_proof
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
    Predicate,
    Provenance,
    Result,
    Runner,
    Runtime,
    Subject,
    VCRError,
    Verdict,
)
from checkseal.profile import validate_n1_profile
from checkseal.seal import sign_local
from checkseal.trust import check_invariant_e1, render_trust_floor, trust_floor
from checkseal.verify import _freshness, _verify_entries

BIND = {Enforced.ENFORCED: 2, Enforced.ADVISORY: 1, Enforced.OBSERVED: 0}
GRADE = {Grade.A: 2, Grade.B: 1, Grade.C: 0}
CONFIG = sha256_hex(b"config")
CLASS_ID = "guard/destructive-execution"


def entry(
    *,
    enforced: Enforced,
    grade: Grade,
    authority: Authority = Authority.OPERATOR,
    config_ref: str | None = CONFIG,
    proof: EnforcedProof | None = None,
    result: Result = Result.PASS,
) -> CheckEntry:
    return CheckEntry(
        check=Check(id=CLASS_ID, kind=CheckKind.GUARD, version="1", config_ref=config_ref),
        verdict=Verdict(result=result, enforced=enforced, enforced_proof=proof),
        evidence=Evidence(kind=EvidenceKind.EXIT_CODE, grade=grade, digest=sha256_hex(b"e")),
        runtime=Runtime(ran_at="t", runner=Runner.CI),
        provenance=Provenance(authority=authority),
    )


# INV-P1: trust floor ---------------------------------------------------------


@pytest.mark.parametrize(("enforced", "grade"), list(itertools.product(Enforced, Grade)))
def test_trust_floor_is_min_and_never_a_bare_word(enforced: Enforced, grade: Grade) -> None:
    e = entry(enforced=enforced, grade=grade)
    assert trust_floor(e) == min(BIND[enforced], GRADE[grade])
    label = render_trust_floor(e)
    assert label in {"enforced + reproducible", "surfaced", "telemetry only"}
    assert label not in {v.value for v in Enforced}


# INV-P2: E1 ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("enforced", "grade", "has_config"), list(itertools.product(Enforced, Grade, [True, False]))
)
def test_e1_enforced_needs_reproducible_evidence(enforced: Enforced, grade: Grade, has_config: bool) -> None:
    e = entry(enforced=enforced, grade=grade, config_ref=CONFIG if has_config else None)
    allowed = enforced is not Enforced.ENFORCED or grade is Grade.A or (grade is Grade.B and has_config)
    if allowed:
        check_invariant_e1(e)
    else:
        with pytest.raises(VCRError, match="E1"):
            check_invariant_e1(e)


# INV-P3: N1 profile + tier rule at sealing ------------------------------------

_PROOF = EnforcedProof(sha256=sha256_hex(b"r"), uri="mem://r")


@pytest.mark.parametrize(
    ("enforced", "grade", "authority", "with_proof", "public"),
    list(itertools.product(Enforced, Grade, Authority, [True, False], [True, False])),
)
def test_n1_profile_and_public_tier_rule(
    enforced: Enforced, grade: Grade, authority: Authority, with_proof: bool, public: bool
) -> None:
    e = entry(enforced=enforced, grade=grade, authority=authority, proof=_PROOF if with_proof else None)
    predicate = Predicate(subject=Subject(kind="artifact", digest=sha256_hex(b"s"), name="n"), checks=[e])
    e1_ok = enforced is not Enforced.ENFORCED or grade in (Grade.A, Grade.B)
    grade_c_ok = grade is not Grade.C or authority is Authority.OPERATOR
    proof_ok = not (public and enforced is Enforced.ENFORCED and not with_proof)
    profile_ok = e1_ok and grade_c_ok and proof_ok
    if profile_ok:
        validate_n1_profile(predicate, public=public)
    else:
        with pytest.raises(VCRError):
            validate_n1_profile(predicate, public=public)
    # A T1 signer can never mint a public seal, whatever the content.
    if public or not profile_ok:
        with pytest.raises(VCRError):
            sign_local(predicate, SIGNER, public=public)
    else:
        sign_local(predicate, SIGNER, public=public)


def test_n1_profile_refuses_an_empty_predicate() -> None:
    predicate = Predicate(subject=Subject(kind="artifact", digest=sha256_hex(b"s"), name="n"), checks=[])
    with pytest.raises(VCRError, match="at least one check"):
        validate_n1_profile(predicate, public=False)


# INV-P4: the verifier's per-entry decision table (proven by exhaustion) --------

_REEXEC = {
    "none": None,
    "confirms": lambda _e: True,
    "denies": lambda _e: False,
    "raises": lambda _e: (_ for _ in ()).throw(RuntimeError("boom")),
}


def _hb(config_sha: str | None = CONFIG, **over: Any) -> bytes:
    report: dict[str, Any] = {
        "schema": "harnessbench-report/v1",
        "corpus": "asi05-destructive-execution",
        "ees": 1.0,
        "verdicts": {"enforced": 5, "advised": 0, "permitted": 1, "errors": 0},
        "n": 6,
    }
    if config_sha is not None:
        report["config_sha256"] = config_sha
    report.update(over)
    return json.dumps(report).encode()


_GOOD = _hb()
_LOADERS = {
    "none": None,
    "resolves": lambda _u: _GOOD,
    "wrong bytes": lambda _u: _GOOD + b" ",
    "raises": lambda _u: (_ for _ in ()).throw(OSError("gone")),
}


@pytest.mark.parametrize(
    ("enforced", "grade", "authority", "with_proof", "reexec", "loader", "allow_external", "has_config"),
    list(
        itertools.product(
            Enforced, Grade, Authority, [True, False], _REEXEC, _LOADERS, [True, False], [True, False]
        )
    ),
)
def test_verifier_entry_decision_table(
    enforced: Enforced,
    grade: Grade,
    authority: Authority,
    with_proof: bool,
    reexec: str,
    loader: str,
    allow_external: bool,
    has_config: bool,
) -> None:
    proof = EnforcedProof(sha256=sha256_hex(_GOOD), uri="mem://hb") if with_proof else None
    e = entry(
        enforced=enforced,
        grade=grade,
        authority=authority,
        proof=proof,
        config_ref=CONFIG if has_config else None,
    )
    predicate = Predicate(subject=Subject(kind="artifact", digest=sha256_hex(b"s"), name="n"), checks=[e])
    calls: list[str] = []

    def spy_reexec(x: CheckEntry) -> bool:
        calls.append("reexec")
        fn = _REEXEC[reexec]
        assert fn is not None
        return bool(fn(x))

    def spy_loader(u: str) -> bytes:
        calls.append("loader")
        fn = _LOADERS[loader]
        assert fn is not None
        return bytes(fn(u))

    [finding] = _verify_entries(
        predicate,
        reexecutor=spy_reexec if _REEXEC[reexec] is not None else None,
        loader=spy_loader if _LOADERS[loader] is not None else None,
        attested_authority=False,
        allow_external=allow_external,
    )
    e1_ok = enforced is not Enforced.ENFORCED or grade is Grade.A or (grade is Grade.B and has_config)
    needs_reexec = enforced is Enforced.ENFORCED and grade is Grade.A
    reexec_ok = not needs_reexec or reexec == "confirms"
    if with_proof:
        proof_ok = loader == "resolves" and has_config
    else:
        proof_ok = enforced is not Enforced.ENFORCED
    grade_c_ok = grade is not Grade.C or authority is Authority.OPERATOR
    expected = allow_external and e1_ok and reexec_ok and proof_ok and grade_c_ok
    assert finding.trusted is expected, finding
    assert finding.trust_floor == min(BIND[enforced], GRADE[grade])
    if not allow_external or not e1_ok:
        assert calls == [], "external work ran on an unauthenticated or E1-violating entry"


# INV-P5: enforced_proof binding ----------------------------------------------


@given(st.data())
def test_any_byte_flip_of_the_proof_report_unresolves_it(data: st.DataObject) -> None:
    raw = bytearray(_GOOD)
    raw[data.draw(st.integers(0, len(raw) - 1))] ^= data.draw(st.integers(1, 255))
    e = entry(enforced=Enforced.ENFORCED, grade=Grade.A)
    res = resolve_enforced_proof(
        e, EnforcedProof(sha256=sha256_hex(_GOOD), uri="u"), loader=lambda _u: bytes(raw)
    )
    assert not res.resolved
    assert resolve_enforced_proof(
        e, EnforcedProof(sha256=sha256_hex(_GOOD), uri="u"), loader=lambda _u: _GOOD
    ).resolved


@given(
    st.one_of(st.none(), sha_hex),
    st.sampled_from(["asi05-destructive-execution", "asi01-prompt-injection", "rights-gate"]),
    st.floats(allow_nan=True, allow_infinity=True),
    st.integers(-1, 5),
    st.integers(-1, 5),
)
def test_proof_resolves_only_with_config_binding_class_match_and_enforcing_report(
    declared: str | None, corpus: str, ees: float, enforced_n: int, advised_n: int
) -> None:
    raw = _hb(
        config_sha=declared,
        corpus=corpus,
        ees=ees,
        verdicts={"enforced": enforced_n, "advised": advised_n, "permitted": 0, "errors": 0},
    )
    e = entry(enforced=Enforced.ENFORCED, grade=Grade.A)
    res = resolve_enforced_proof(e, EnforcedProof(sha256=sha256_hex(raw), uri="u"), loader=lambda _u: raw)
    expected = (
        declared == CONFIG
        and corpus == "asi05-destructive-execution"
        and ees == ees
        and EES_FLOOR <= ees <= 1.0
        and enforced_n > 0
        and advised_n == 0
    )
    assert res.resolved is expected, res.reason


# INV-P6: freshness fails closed ----------------------------------------------


@given(
    st.one_of(st.none(), st.integers(0, 10**6)),
    st.one_of(
        st.none(),
        st.integers(-(10**9), 2 * 10**9),
        st.integers(0, 2 * 10**9).map(str),
        st.text(max_size=5),
        st.just([]),
    ),
    st.floats(0, 2 * 10**9, allow_nan=False),
    st.sampled_from(["normal", "no tlog", "not json", "empty list"]),
)
def test_freshness_bound_fails_closed(max_age: int | None, integrated: Any, now: float, shape: str) -> None:
    entry_obj: dict[str, Any] = {} if integrated is None else {"integratedTime": integrated}
    bundle: Any = {"verificationMaterial": {"tlogEntries": [entry_obj]}}
    if shape == "no tlog":
        bundle = {"verificationMaterial": {}}
    elif shape == "empty list":
        bundle = {"verificationMaterial": {"tlogEntries": []}}
    text = "{not json" if shape == "not json" else json.dumps(bundle)
    ok, _reason = _freshness(text, max_age_seconds=max_age, now=now)
    if max_age is None:
        assert ok
        return
    try:
        t = int(integrated) if shape == "normal" and integrated is not None else 0
    except (TypeError, ValueError):
        t = 0
    assert ok is (t > 0 and now - t <= max_age)


# INV-P7: keyless (T2) path gates external work on subject + freshness ---------


@given(
    seal_cases(max_checks=2),
    st.booleans(),
    st.one_of(st.none(), st.integers(0, 1000)),
    st.integers(0, 2000),
)
def test_keyless_path_runs_external_work_only_after_subject_and_freshness(
    case: SealCase, subject_matches: bool, max_age: int | None, age: int
) -> None:
    """The Sigstore call itself is stubbed (no network): this checks only the
    local decisions verify_keyless_seal makes after sigstore returns."""
    from unittest import mock

    from checkseal.sign.base import Identity, SigningTier
    from checkseal.verify import verify_keyless_seal

    now = 1_800_000_000.0
    bundle = json.dumps({"verificationMaterial": {"tlogEntries": [{"integratedTime": str(int(now) - age)}]}})
    identity = Identity(tier=SigningTier.T2, subject="ci@example.invalid", attested_authority=True)
    calls: list[str] = []

    def reexec(_e: CheckEntry) -> bool:
        calls.append("reexec")
        return True

    def loader(uri: str) -> bytes:
        calls.append("loader")
        return case.proofs[uri]

    with mock.patch(
        "checkseal.sign.keyless.verify_bundle_keyless", return_value=(case.envelope.payload, identity)
    ):
        report = verify_keyless_seal(
            bundle,
            expected_identity="ci@example.invalid",
            expected_issuer="https://issuer.example.invalid",
            subject_bytes=case.artifact if subject_matches else case.artifact + b"?",
            reexecutor=reexec,
            loader=loader,
            max_age_seconds=max_age,
            now=now,
        )
    fresh = max_age is None or age <= max_age
    gate_open = subject_matches and fresh
    assert report.authentic is gate_open
    if not gate_open:
        assert calls == []
