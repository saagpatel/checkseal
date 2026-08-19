"""Ingest + seal an OPERANT-J judge sitting (the observed lane on a real signature)."""

from __future__ import annotations

import json

import pytest

from checkseal.digest import sha256_hex
from checkseal.model import (
    CheckKind,
    Enforced,
    EvidenceKind,
    Grade,
    Result,
    VCRError,
)
from checkseal.operantj import entry_from_vcr_v01, ingest_operant_j_receipt, read_receipt
from checkseal.profile import validate_n1_profile
from checkseal.seal import assemble, sign_local
from checkseal.store import CheckResult, JsonlSealStore
from checkseal.trust import render_trust_floor
from checkseal.verify import verify_local_seal

VCR_V01 = "https://saagarpatel.dev/schema/vcr/v0.1"
_CONFIG_REF = sha256_hex(b"frozen-docket+answers+rubric")


def _vcr_record(case_id: str, result: str, *, enforced: str = "observed", proof: bool = False) -> dict:
    """A minimal vcr-core v0.1 in-toto statement, shaped like operantj/emit_vcr.py output."""
    verdict: dict = {"result": result, "enforced": enforced, "score": 0.9}
    if proof:
        verdict["enforced_proof"] = {"sha256": sha256_hex(b"x"), "uri": "x"}
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": VCR_V01,
        "subject": [
            {
                "kind": "harness_config",
                "name": "operant-j/gemini-3.1-pro-high+v1.1",
                "mediaType": "application/x-operant-j-judge",
                "digest": {"sha256": "sha256:" + sha256_hex(b"judge-subject")},
            }
        ],
        "predicate": {
            "check": {
                "id": f"operantj/{case_id}",
                "category": "quality",
                "version": "docket-refusal-probe",
                "config_ref": {"sha256": "sha256:" + _CONFIG_REF},
            },
            "verdict": verdict,
            "evidence": {
                "kind": "judge-verdict-digest",
                "grade": "B",
                "digest": {"sha256": "sha256:" + sha256_hex(case_id.encode())},
            },
            "runtime": {
                "ran_at": "2026-08-18T00:00:00Z",
                "runner": "operant-j/agy@v1",
                "env_digest": {"sha256": "sha256:" + sha256_hex(b"env")},
            },
            "provenance": {
                "authority": "operator",
                "trust": "trusted",
                "instruction_boundary": "direct",
            },
        },
    }


def _write_receipt(path, records: list[dict]) -> str:
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records), encoding="utf-8")
    return str(path)


def _sample_receipt(tmp_path):
    # a realistic mixed sitting: one correct case (pass), one wrong (fail), one dead dispatch (error)
    records = [
        _vcr_record("ref-window-deploy", "pass"),
        _vcr_record("ref-window-backup", "fail"),
        _vcr_record("ref-window-restore", "error"),
    ]
    return _write_receipt(tmp_path / "vcr-run.jsonl", records)


def test_ingest_maps_every_case_to_an_observed_review_check(tmp_path):
    receipt = _sample_receipt(tmp_path)
    subject, entries = ingest_operant_j_receipt(receipt)

    assert len(entries) == 3  # no case dropped
    assert subject.name == "operant-j/gemini-3.1-pro-high+v1.1"
    for entry in entries:
        assert entry.verdict.enforced is Enforced.OBSERVED  # a benchmark observes, never enforces
        assert entry.verdict.enforced_proof is None
        assert entry.check.kind is CheckKind.REVIEW  # a judge is a reviewer
        assert entry.evidence.kind is EvidenceKind.TRANSCRIPT_DIGEST
        assert entry.evidence.grade is Grade.B
        assert entry.check.config_ref == _CONFIG_REF  # sha256: prefix stripped to bare hex
        assert len(entry.evidence.digest) == 64  # bare hex, not sha256:-prefixed
        assert render_trust_floor(entry) == "telemetry only"  # observed + B

    results = [e.verdict.result for e in entries]
    assert results == [Result.PASS, Result.FAIL, Result.ERROR]


def test_ingested_predicate_passes_the_n1_profile_public_and_private(tmp_path):
    receipt = _sample_receipt(tmp_path)
    subject, entries = ingest_operant_j_receipt(receipt)
    store = JsonlSealStore(str(tmp_path / "store.jsonl"))
    for entry in entries:
        store.append(CheckResult(subject, entry))
    predicate = assemble(store, subject)
    # observed needs no enforced_proof, so an observed sitting is publishable under N1.
    validate_n1_profile(predicate, public=False)
    validate_n1_profile(predicate, public=True)


def test_seal_round_trips_through_sign_and_verify(tmp_path, local_signer):
    receipt = _sample_receipt(tmp_path)
    subject, entries = ingest_operant_j_receipt(receipt)
    store = JsonlSealStore(str(tmp_path / "store.jsonl"))
    for entry in entries:
        store.append(CheckResult(subject, entry))
    predicate = assemble(store, subject)
    seal = sign_local(predicate, local_signer, public=False)
    seal_path = tmp_path / "operant-j.intoto.jsonl"
    seal_path.write_text(seal.to_intoto_jsonl() + "\n", encoding="utf-8")

    report = verify_local_seal(str(seal_path), local_signer.verifier(), subject_path=receipt)
    assert report.subject_digest_ok  # the receipt is intact
    assert report.signature_ok
    assert report.authentic
    # every observed check is trusted; result_ok mirrors the judge's own verdict per case
    by_result = {e.check_id.rsplit("/", 1)[-1]: e for e in report.entries}
    assert all(e.trusted for e in report.entries)
    assert by_result["ref-window-deploy"].result_ok is True
    assert by_result["ref-window-backup"].result_ok is False
    assert by_result["ref-window-restore"].result_ok is False


def test_tampered_receipt_breaks_the_subject_digest(tmp_path, local_signer):
    receipt = _sample_receipt(tmp_path)
    subject, entries = ingest_operant_j_receipt(receipt)
    store = JsonlSealStore(str(tmp_path / "store.jsonl"))
    for entry in entries:
        store.append(CheckResult(subject, entry))
    seal = sign_local(assemble(store, subject), local_signer, public=False)
    seal_path = tmp_path / "operant-j.intoto.jsonl"
    seal_path.write_text(seal.to_intoto_jsonl() + "\n", encoding="utf-8")

    # someone edits the receipt after it was sealed
    with open(receipt, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(_vcr_record("ref-window-extra", "pass")) + "\n")

    report = verify_local_seal(str(seal_path), local_signer.verifier(), subject_path=receipt)
    assert report.subject_digest_ok is False  # the seal is bound to the original bytes
    assert report.authentic is False


def test_refuses_an_enforced_record(tmp_path):
    rec = _vcr_record("ref-window-deploy", "pass", enforced="enforced")
    with pytest.raises(VCRError, match="observed lane"):
        entry_from_vcr_v01(rec)


def test_refuses_an_enforced_proof_pointer(tmp_path):
    rec = _vcr_record("ref-window-deploy", "pass", proof=True)
    with pytest.raises(VCRError, match="enforced_proof"):
        entry_from_vcr_v01(rec)


def test_refuses_a_non_vcr_record():
    with pytest.raises(VCRError, match="vcr-core v0.1"):
        entry_from_vcr_v01({"predicateType": "https://example.com/other", "predicate": {}})


def test_refuses_an_empty_receipt(tmp_path):
    empty = tmp_path / "vcr-empty.jsonl"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(VCRError, match="empty"):
        read_receipt(str(empty))


def test_refuses_a_malformed_check_id_at_ingest(tmp_path):
    rec = _vcr_record("ref-window-deploy", "pass")
    rec["predicate"]["check"]["id"] = "operantj/Bad Id"  # uppercase + space violate the id regex
    with pytest.raises(VCRError):
        entry_from_vcr_v01(rec)


def test_refuses_a_missing_result_at_ingest(tmp_path):
    rec = _vcr_record("ref-window-deploy", "pass")
    del rec["predicate"]["verdict"]["result"]
    with pytest.raises(VCRError):
        entry_from_vcr_v01(rec)


def test_refuses_an_oversized_subject_name_at_ingest(tmp_path):
    rec = _vcr_record("ref-window-deploy", "pass")
    rec["subject"][0]["name"] = "x" * 300  # exceeds the model's 256-char subject-name cap
    receipt = _write_receipt(tmp_path / "vcr-big.jsonl", [rec])
    with pytest.raises(VCRError):
        ingest_operant_j_receipt(receipt)


def test_read_receipt_refuses_a_malformed_json_line(tmp_path):
    p = tmp_path / "vcr-bad.jsonl"
    p.write_text('{"ok": true}\nnot json\n', encoding="utf-8")
    with pytest.raises(VCRError, match="malformed JSON"):
        read_receipt(str(p))
