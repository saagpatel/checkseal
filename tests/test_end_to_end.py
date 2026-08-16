from __future__ import annotations

from conftest import make_entry, make_subject, write_hb_report

from checkseal.digest import sha256_hex
from checkseal.model import CheckKind, Enforced, EvidenceKind, Grade, Result
from checkseal.seal import assemble, sign_local
from checkseal.store import CheckResult, JsonlSealStore


def _seal_two_checks(tmp_path, signer, proof):
    content = b"tool artifact bytes"
    subject_file = tmp_path / "artifact.txt"
    subject_file.write_bytes(content)
    subject = make_subject(content=content, name="tool/core-guard")

    guard = make_entry(
        check_id="guard/destructive-execution",
        enforced=Enforced.ENFORCED,
        grade=Grade.A,
        proof=proof,
    )
    factcheck = make_entry(
        check_id="review/fact-check",
        kind=CheckKind.REVIEW,
        enforced=Enforced.ADVISORY,
        grade=Grade.B,
        evidence_kind=EvidenceKind.TRANSCRIPT_DIGEST,
        result=Result.PASS,
        config_ref=None,
    )

    store = JsonlSealStore(str(tmp_path / "t0.jsonl"))
    store.append(CheckResult(subject, guard))
    store.append(CheckResult(subject, factcheck))

    predicate = assemble(store, subject)
    seal = sign_local(predicate, signer, public=False)
    seal_path = tmp_path / "seal.intoto.jsonl"
    seal_path.write_text(seal.to_intoto_jsonl() + "\n")
    return subject_file, seal_path


def test_seal_and_verify_happy_path(tmp_path, local_signer):
    from checkseal.verify import verify_local_seal

    proof = write_hb_report(tmp_path / "hb.json")
    subject_file, seal_path = _seal_two_checks(tmp_path, local_signer, proof)

    verifier = local_signer.verifier()
    report = verify_local_seal(
        str(seal_path),
        verifier,
        subject_path=str(subject_file),
        reexecutor=lambda _e: True,
    )
    assert report.ok, report.render()
    assert report.subject_digest_ok
    assert report.signature_ok
    guard = next(e for e in report.entries if e.check_id == "guard/destructive-execution")
    assert guard.reexecution == "confirmed"
    assert "resolved" in guard.enforced_proof


def test_tampered_subject_is_caught(tmp_path, local_signer):
    from checkseal.verify import verify_local_seal

    proof = write_hb_report(tmp_path / "hb.json")
    _subject, seal_path = _seal_two_checks(tmp_path, local_signer, proof)
    tampered = tmp_path / "tampered.txt"
    tampered.write_bytes(b"a different artifact")

    verifier = local_signer.verifier()
    report = verify_local_seal(
        str(seal_path), verifier, subject_path=str(tampered), reexecutor=lambda _e: True
    )
    assert not report.subject_digest_ok
    assert not report.ok


def test_wrong_key_fails_signature(tmp_path, local_signer):
    from checkseal.sign.local import LocalKeySigner
    from checkseal.verify import verify_local_seal

    proof = write_hb_report(tmp_path / "hb.json")
    subject_file, seal_path = _seal_two_checks(tmp_path, local_signer, proof)

    other = LocalKeySigner.generate()
    report = verify_local_seal(
        str(seal_path),
        other.verifier(),
        subject_path=str(subject_file),
        reexecutor=lambda _e: True,
    )
    assert not report.signature_ok
    assert not report.ok


def test_enforced_grade_a_without_reexecutor_is_not_trusted(tmp_path, local_signer):
    from checkseal.verify import verify_local_seal

    proof = write_hb_report(tmp_path / "hb.json")
    subject_file, seal_path = _seal_two_checks(tmp_path, local_signer, proof)

    report = verify_local_seal(
        str(seal_path),
        local_signer.verifier(),
        subject_path=str(subject_file),
        reexecutor=None,  # no re-execution supplied
    )
    guard = next(e for e in report.entries if e.check_id == "guard/destructive-execution")
    assert guard.reexecution.startswith("not-run")
    assert not guard.ok
    assert not report.ok


def test_cli_keygen_seal_verify(tmp_path):
    from checkseal.__main__ import main

    key = tmp_path / "k.pem"
    pub = tmp_path / "k.pub.pem"
    assert main(["keygen", "--out", str(key), "--pub", str(pub)]) == 0

    content = b"cli subject"
    subject_file = tmp_path / "art.txt"
    subject_file.write_bytes(content)

    # Seed the store with one advisory check for the subject (no proof needed).
    from checkseal.store import CheckResult, JsonlSealStore

    entry = make_entry(
        check_id="review/editorial",
        kind=CheckKind.REVIEW,
        enforced=Enforced.ADVISORY,
        grade=Grade.B,
        evidence_kind=EvidenceKind.LOG_DIGEST,
        config_ref=None,
    )
    subject = make_subject(content=content, name="cli/artifact")
    store = JsonlSealStore(str(tmp_path / "t0.jsonl"))
    store.append(CheckResult(subject, entry))

    seal = tmp_path / "seal.intoto.jsonl"
    rc = main(
        [
            "seal",
            "--store",
            str(tmp_path / "t0.jsonl"),
            "--subject",
            str(subject_file),
            "--name",
            "cli/artifact",
            "--key",
            str(key),
            "--out",
            str(seal),
        ]
    )
    assert rc == 0
    rc = main(["verify", str(seal), "--subject", str(subject_file), "--pubkey", str(pub)])
    assert rc == 0
