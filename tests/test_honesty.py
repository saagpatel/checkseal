"""The flagship property: the verifier cannot be made to bless an over-claim.

A signed 'passed' can be a signed lie. These tests exercise the machinery that
makes the enforced grade honest: enforced_proof must resolve to a HarnessBench
report whose corpus threat-class actually covers the check.
"""

from __future__ import annotations

from conftest import make_entry, make_subject, write_hb_report

from checkseal.hbresolve import resolve_enforced_proof
from checkseal.model import Enforced, Grade
from checkseal.seal import assemble, sign_local
from checkseal.store import CheckResult, JsonlSealStore


def test_matching_corpus_resolves(tmp_path):
    proof = write_hb_report(tmp_path / "hb.json", corpus="asi05-destructive-execution")
    entry = make_entry(check_id="guard/destructive-execution", proof=proof)
    res = resolve_enforced_proof(entry, proof)
    assert res.resolved, res.reason
    assert res.threat_class == "destructive-execution"


def test_corpus_mismatch_is_unproven(tmp_path):
    # A content rights-gate CANNOT be proven by a destructive-execution corpus.
    proof = write_hb_report(tmp_path / "hb.json", corpus="asi05-destructive-execution")
    entry = make_entry(check_id="review/rights-gate", proof=proof)
    res = resolve_enforced_proof(entry, proof)
    assert not res.resolved
    assert "corpus mismatch" in res.reason


def test_digest_mismatch_is_unproven(tmp_path):
    proof = write_hb_report(tmp_path / "hb.json")
    # rewrite the report so its bytes no longer match proof.sha256
    (tmp_path / "hb.json").write_bytes(b'{"schema":"harnessbench-report/v1","corpus":"x"}')
    entry = make_entry(check_id="guard/destructive-execution", proof=proof)
    res = resolve_enforced_proof(entry, proof)
    assert not res.resolved
    assert "content digest" in res.reason


def test_config_that_only_advises_is_unproven(tmp_path):
    proof = write_hb_report(tmp_path / "hb.json", enforced=0, advised=46)
    entry = make_entry(check_id="guard/destructive-execution", proof=proof)
    res = resolve_enforced_proof(entry, proof)
    assert not res.resolved
    assert "does not enforce" in res.reason


def test_full_verify_rejects_the_over_claim(tmp_path, local_signer):
    """End to end: a sealed, correctly-signed over-claim still fails verify."""
    from checkseal.sign.local import LocalKeyVerifier
    from checkseal.verify import verify_local_seal

    content = b"an essay claiming a rights-gate it cannot prove"
    subject_file = tmp_path / "essay.md"
    subject_file.write_bytes(content)
    subject = make_subject(content=content, name="essay/stranded")

    # destructive-execution proof mis-applied to a rights-gate check
    proof = write_hb_report(tmp_path / "hb.json", corpus="asi05-destructive-execution")
    entry = make_entry(check_id="review/rights-gate", enforced=Enforced.ENFORCED, grade=Grade.A, proof=proof)
    store = JsonlSealStore(str(tmp_path / "t0.jsonl"))
    store.append(CheckResult(subject, entry))
    seal = sign_local(assemble(store, subject), local_signer, public=False)
    seal_path = tmp_path / "seal.intoto.jsonl"
    seal_path.write_text(seal.to_intoto_jsonl() + "\n")

    report = verify_local_seal(
        str(seal_path),
        LocalKeyVerifier(local_signer._key.public_key()),
        subject_path=str(subject_file),
        reexecutor=lambda _e: True,  # even with re-execution "confirmed"...
    )
    # ...the seal still fails, because the proof does not cover the check.
    assert report.signature_ok and report.subject_digest_ok
    rg = next(e for e in report.entries if e.check_id == "review/rights-gate")
    assert "corpus mismatch" in rg.enforced_proof
    assert not rg.ok
    assert not report.ok
