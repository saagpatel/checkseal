from __future__ import annotations

from checkseal.sign.base import Identity, SigningTier
from checkseal.sign.local import LocalKeySigner
from checkseal.verify import load_envelope, verify_keyless_seal, verify_local_seal
from conftest import write_hb_report
from test_end_to_end import _seal_two_checks


def test_bad_signature_does_not_call_external_callbacks(tmp_path):
    signer = LocalKeySigner.generate()
    other = LocalKeySigner.generate()
    proof = write_hb_report(tmp_path / "hb.json")
    subject, seal = _seal_two_checks(tmp_path, signer, proof)
    called = []
    report = verify_local_seal(
        str(seal),
        other.verifier(),
        subject_path=str(subject),
        reexecutor=lambda _entry: called.append("reexec") or True,
        loader=lambda _uri: called.append("loader") or b"{}",
    )
    assert not report.signature_ok
    assert called == []


def test_wrong_subject_does_not_call_external_callbacks(tmp_path):
    signer = LocalKeySigner.generate()
    proof = write_hb_report(tmp_path / "hb.json")
    subject, seal = _seal_two_checks(tmp_path, signer, proof)
    other_subject = tmp_path / "wrong.txt"
    other_subject.write_text("wrong")
    called = []
    report = verify_local_seal(
        str(seal),
        signer.verifier(),
        subject_path=str(other_subject),
        reexecutor=lambda _entry: called.append("reexec") or True,
        loader=lambda _uri: called.append("loader") or b"{}",
    )
    assert not report.subject_digest_ok
    assert called == []


def test_stale_keyless_bundle_does_not_call_external_callbacks(tmp_path, monkeypatch):
    import checkseal.sign.keyless as keyless

    signer = LocalKeySigner.generate()
    proof = write_hb_report(tmp_path / "hb.json")
    subject, seal_path = _seal_two_checks(tmp_path, signer, proof)
    payload = load_envelope(str(seal_path)).payload
    identity = Identity(tier=SigningTier.T2, subject="ci@example", attested_authority=True)
    monkeypatch.setattr(keyless, "verify_bundle_keyless", lambda *_args, **_kwargs: (payload, identity))
    called = []
    report = verify_keyless_seal(
        '{"verificationMaterial":{"tlogEntries":[{"integratedTime":1}]}}',
        expected_identity="ci@example",
        expected_issuer="issuer",
        subject_path=str(subject),
        reexecutor=lambda _entry: called.append("reexec") or True,
        loader=lambda _uri: called.append("loader") or b"{}",
        max_age_seconds=1,
        now=100,
    )
    assert not report.freshness_ok
    assert called == []
