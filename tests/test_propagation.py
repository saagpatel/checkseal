"""Regression tests for the review findings: false-PASS propagation gaps and the
forgeable corpus-relevance bypass. Each test would pass against the pre-fix code
and must fail if the fix regresses.
"""

from __future__ import annotations

from checkseal.digest import sha256_hex
from checkseal.hbresolve import default_report_loader, resolve_enforced_proof
from checkseal.model import Enforced, EnforcedProof, EvidenceKind, Grade, Result
from checkseal.seal import assemble, sign_local
from checkseal.store import CheckResult, JsonlSealStore
from checkseal.verify import _freshness, verify_local_seal
from conftest import VALID_SHA, make_entry, make_subject, write_hb_report

# --- the forgeable corpus-relevance bypass (HIGH) ---


def test_rename_attack_is_defeated_by_strong_binding(tmp_path):
    # check.id renamed so its class matches the corpus, but no config_sha256 bind.
    proof = write_hb_report(tmp_path / "hb.json", corpus="asi05-destructive-execution", config_sha256=None)
    entry = make_entry(check_id="review/destructive-execution", proof=proof)
    res = resolve_enforced_proof(entry, proof, loader=default_report_loader)
    assert not res.resolved
    assert "weak binding" in res.reason


def test_config_sha_mismatch_is_unproven(tmp_path):
    proof = write_hb_report(tmp_path / "hb.json", config_sha256="0" * 64)
    entry = make_entry(check_id="guard/destructive-execution", proof=proof)  # config_ref=VALID_SHA
    res = resolve_enforced_proof(entry, proof, loader=default_report_loader)
    assert not res.resolved
    assert "weak binding" in res.reason


def test_strong_binding_resolves(tmp_path):
    proof = write_hb_report(tmp_path / "hb.json", config_sha256=VALID_SHA)
    entry = make_entry(check_id="guard/destructive-execution", proof=proof)
    res = resolve_enforced_proof(entry, proof, loader=default_report_loader)
    assert res.resolved and res.strong_binding


def test_low_ees_is_unproven(tmp_path):
    proof = write_hb_report(tmp_path / "hb.json", ees=0.1)
    entry = make_entry(check_id="guard/destructive-execution", proof=proof)
    res = resolve_enforced_proof(entry, proof, loader=default_report_loader)
    assert not res.resolved
    assert "efficacy" in res.reason


def test_malformed_proof_values_propagate_as_unresolved():
    malformed_reports = [
        b"[]",
        b'{"schema":"harnessbench-report/v1","corpus":"asi05-destructive-execution","ees":NaN,"verdicts":{"enforced":1,"advised":0,"permitted":1,"errors":0},"n":2}',
        b'{"schema":"harnessbench-report/v1","corpus":"asi05-destructive-execution","ees":1,"verdicts":{"enforced":1.0,"advised":0,"permitted":1,"errors":0},"n":2}',
    ]
    for raw in malformed_reports:
        proof = EnforcedProof(sha256=sha256_hex(raw), uri="test-report")
        result = resolve_enforced_proof(make_entry(), proof, loader=lambda _uri, raw=raw: raw)
        assert not result.resolved
        assert result.reason.startswith("gate unproven:")


# --- verdict.result must propagate (HIGH) ---


def test_failing_result_fails_the_verdict(tmp_path, local_signer):
    content = b"an artifact whose check failed"
    subject_file = tmp_path / "art.txt"
    subject_file.write_bytes(content)
    subject = make_subject(content=content, name="tool/thing")
    entry = make_entry(
        check_id="review/fact-check",
        enforced=Enforced.ADVISORY,
        grade=Grade.B,
        evidence_kind=EvidenceKind.TRANSCRIPT_DIGEST,
        result=Result.FAIL,
        config_ref=None,
    )
    store = JsonlSealStore(str(tmp_path / "t0.jsonl"))
    store.append(CheckResult(subject, entry))
    seal = sign_local(assemble(store, subject), local_signer, public=False)
    (tmp_path / "seal.intoto.jsonl").write_text(seal.to_intoto_jsonl() + "\n")

    report = verify_local_seal(
        str(tmp_path / "seal.intoto.jsonl"),
        local_signer.verifier(),
        subject_path=str(subject_file),
    )
    # The seal is authentic (properly signed, digest-bound) but the check FAILED,
    # so the overall verdict must not be PASS.
    assert report.authentic
    assert not report.checks_passed
    assert not report.ok


# --- freshness must fail closed when a bound is requested (HIGH) ---


def test_freshness_no_bound_ok():
    ok, _ = _freshness("{}", max_age_seconds=None, now=1000.0)
    assert ok


def test_freshness_stale_fails():
    bundle = '{"verificationMaterial":{"tlogEntries":[{"integratedTime":100}]}}'
    ok, reason = _freshness(bundle, max_age_seconds=10, now=1000.0)
    assert not ok and "STALE" in reason


def test_freshness_unreadable_fails_closed():
    ok, reason = _freshness("{}", max_age_seconds=10, now=1000.0)
    assert not ok and "fail closed" in reason


def test_freshness_within_bound_ok():
    bundle = '{"verificationMaterial":{"tlogEntries":[{"integratedTime":995}]}}'
    ok, reason = _freshness(bundle, max_age_seconds=10, now=1000.0)
    assert ok and "fresh" in reason
