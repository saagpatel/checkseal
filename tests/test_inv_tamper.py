"""Tamper-refusal invariants for T1 seals (INV-T*), against the real verifier.

Site claim: "flip one byte of the signed payload and the verifier refuses."
"Signed payload" here is read as the bytes the signature covers: the decoded
DSSE payload inside PAE(payloadType, payload). The envelope file is a base64 and
JSON encoding of those bytes; INV-T9 pins what happens at that layer.
"""

from __future__ import annotations

import json
import random
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from _invariant_support import (
    CLI_HANDLED,
    OTHER_SIGNER,
    SIGNER,
    VERIFIER,
    SealCase,
    b64,
    envelope_line,
    resign,
    seal_cases,
    verify_line,
    with_payload,
    with_sig,
)
from checkseal.dsse import PAYLOAD_TYPE, Envelope, Signature, pae
from checkseal.json_utils import loads_unique_json
from checkseal.model import VCRError

ED25519_L = 2**252 + 27742317777372353535851937790883648493


def _assert_refused(line: bytes, case: SealCase, artifact: bytes | None = None) -> None:
    out = verify_line(line, artifact=case.artifact if artifact is None else artifact, case=case)
    assert not out.accepted, out.describe()
    if out.error is not None:
        assert isinstance(out.error, CLI_HANDLED), repr(out.error)


# INV-T0 ---------------------------------------------------------------------


@given(seal_cases())
def test_untampered_seal_verifies(case: SealCase) -> None:
    out = verify_line(case.line, artifact=case.artifact, case=case)
    assert out.accepted, out.describe()
    assert out.report is not None
    assert out.report.ok == all(e.verdict.result.is_ok for e in case.predicate.checks)


# INV-T1 / T2: single byte and single bit flips of the signed payload ----------


@given(seal_cases(), st.data())
def test_any_payload_byte_flip_is_refused(case: SealCase, data: st.DataObject) -> None:
    payload = bytearray(case.envelope.payload)
    i = data.draw(st.integers(0, len(payload) - 1), label="position")
    mask = data.draw(st.integers(1, 255), label="xor mask")
    payload[i] ^= mask
    _assert_refused(with_payload(case, bytes(payload)), case)


@given(seal_cases(), st.data())
def test_any_payload_bit_flip_is_refused(case: SealCase, data: st.DataObject) -> None:
    payload = bytearray(case.envelope.payload)
    i = data.draw(st.integers(0, len(payload) - 1), label="position")
    payload[i] ^= 1 << data.draw(st.integers(0, 7), label="bit")
    _assert_refused(with_payload(case, bytes(payload)), case)


# INV-T3 / T4: truncation and extension ---------------------------------------


@given(seal_cases(), st.data())
def test_any_payload_truncation_is_refused(case: SealCase, data: st.DataObject) -> None:
    payload = case.envelope.payload
    start = data.draw(st.integers(0, len(payload) - 1), label="start")
    end = data.draw(st.integers(start, len(payload)), label="end")
    if start == 0 and end == len(payload):
        end -= 1
    _assert_refused(with_payload(case, payload[start:end]), case)


@given(seal_cases(), st.data())
def test_any_payload_extension_is_refused(case: SealCase, data: st.DataObject) -> None:
    payload = case.envelope.payload
    at = data.draw(st.integers(0, len(payload)), label="insert at")
    extra = data.draw(st.binary(min_size=1, max_size=16), label="inserted")
    _assert_refused(with_payload(case, payload[:at] + extra + payload[at:]), case)


# INV-T5: payloadType is bound ------------------------------------------------


@given(seal_cases(), st.text(max_size=40).filter(lambda t: t != PAYLOAD_TYPE))
def test_payload_type_change_is_refused(case: SealCase, new_type: str) -> None:
    _assert_refused(with_payload(case, case.envelope.payload, payload_type=new_type), case)
    # Independently of the verifier's constant check, the signature itself binds the type.
    sig = case.envelope.signatures[0]
    try:
        VERIFIER.verify(pae(new_type, case.envelope.payload), sig)
    except VCRError:
        return
    raise AssertionError("signature over PAE verified under a different payloadType")


# INV-T6: signature byte flips, truncation, extension, S+L malleability --------


@given(seal_cases(), st.data())
def test_any_signature_mutation_is_refused(case: SealCase, data: st.DataObject) -> None:
    sig = bytearray(case.envelope.signatures[0].sig)
    how = data.draw(st.sampled_from(["byte", "bit", "truncate", "extend"]), label="how")
    if how == "byte":
        sig[data.draw(st.integers(0, len(sig) - 1))] ^= data.draw(st.integers(1, 255))
    elif how == "bit":
        sig[data.draw(st.integers(0, len(sig) - 1))] ^= 1 << data.draw(st.integers(0, 7))
    elif how == "truncate":
        sig = sig[: data.draw(st.integers(1, len(sig) - 1))]
    else:
        sig += data.draw(st.binary(min_size=1, max_size=8))
    _assert_refused(with_sig(case, bytes(sig)), case)


@given(seal_cases())
def test_signature_s_plus_l_malleation_is_refused(case: SealCase) -> None:
    sig = case.envelope.signatures[0].sig
    s = int.from_bytes(sig[32:], "little") + ED25519_L
    if s >= 2**256:
        return
    _assert_refused(with_sig(case, sig[:32] + s.to_bytes(32, "little")), case)


@given(seal_cases())
def test_signature_from_another_key_is_refused(case: SealCase) -> None:
    d = resign(case.envelope.payload, OTHER_SIGNER)
    _assert_refused(envelope_line(d), case)


# INV-T7: subject digest binding ----------------------------------------------


@given(seal_cases(), st.binary(max_size=64))
def test_different_artifact_bytes_are_refused(case: SealCase, other: bytes) -> None:
    if other == case.artifact:
        other = other + b"\x00"
    _assert_refused(case.line, case, artifact=other)


@given(seal_cases(), st.binary(max_size=16))
def test_rewriting_the_sealed_subject_digest_is_refused(case: SealCase, new_artifact: bytes) -> None:
    """Point both subject digests at new bytes, keep the old signature: refused."""
    from checkseal.digest import canonical_bytes, sha256_hex

    new_digest = sha256_hex(new_artifact)
    if new_digest == case.predicate.subject.digest:
        return
    statement = loads_unique_json(case.envelope.payload)
    statement["subject"][0]["digest"]["sha256"] = new_digest
    statement["predicate"]["subject"]["digest"]["sha256"] = new_digest
    line = with_payload(case, canonical_bytes(statement))
    _assert_refused(line, case, artifact=new_artifact)


# INV-T8: gating of external work ---------------------------------------------


@given(seal_cases(), st.sampled_from(["payload", "signature", "artifact", "key"]))
def test_external_work_never_runs_after_auth_or_subject_failure(case: SealCase, what: str) -> None:
    calls: list[str] = []

    def reexecutor(_entry: object) -> bool:
        calls.append("reexec")
        return True

    def loader(uri: str) -> bytes:
        calls.append("loader")
        return case.proofs[uri]

    line, artifact, verifier = case.line, case.artifact, VERIFIER
    if what == "payload":
        # A signed-content edit that still parses: the signature must fail.
        from checkseal.digest import canonical_bytes

        statement = loads_unique_json(case.envelope.payload)
        statement["predicate"]["checks"][0]["check"]["version"] += "x"
        line = with_payload(case, canonical_bytes(statement))
    elif what == "signature":
        sig = bytearray(case.envelope.signatures[0].sig)
        sig[0] ^= 0x01
        line = with_sig(case, bytes(sig))
    elif what == "artifact":
        artifact = case.artifact + b"!"
    else:
        verifier = OTHER_SIGNER.verifier()
        d = case.envelope_dict
        d["signatures"][0].pop("keyid")
        line = envelope_line(d)
    out = verify_line(line, artifact=artifact, verifier=verifier, reexecutor=reexecutor, loader=loader)
    assert not out.accepted
    assert calls == [], f"external work ran despite {what} failure: {calls}"


# INV-T9: envelope-file bytes (base64 and JSON encoding layer) -----------------


def _signed_bytes_of(line: bytes) -> tuple[bytes, bytes]:
    env = Envelope.from_jsonable(loads_unique_json(line.decode("utf-8").splitlines()[0].strip()))
    return pae(env.payload_type, env.payload), env.signatures[0].sig


@given(seal_cases(max_checks=1), st.data())
def test_envelope_file_flip_is_refused_or_authenticates_identical_bytes(
    case: SealCase, data: st.DataObject
) -> None:
    """Any single-byte flip of the .intoto.jsonl file is refused, OR the accepted
    envelope authenticates byte-identical PAE (so the claim about the signed
    payload is untouched). Acceptances are the encoding-layer slack pinned below.
    """
    line = bytearray(case.line)
    i = data.draw(st.integers(0, len(line) - 1), label="file position")
    line[i] ^= data.draw(st.integers(1, 255), label="xor mask")
    out = verify_line(bytes(line), artifact=case.artifact, case=case)
    if out.error is not None:
        assert isinstance(out.error, CLI_HANDLED), repr(out.error)
    if out.accepted:
        assert _signed_bytes_of(bytes(line))[0] == case.envelope.signing_bytes()


def _canonical_case() -> SealCase:
    from checkseal.model import Enforced, EvidenceKind, Grade, Predicate
    from checkseal.seal import sign_local
    from conftest import make_entry, make_subject

    artifact = b"the essay body"
    entry = make_entry(
        enforced=Enforced.ADVISORY, grade=Grade.B, evidence_kind=EvidenceKind.LOG_DIGEST, config_ref=None
    )
    predicate = Predicate(subject=make_subject(artifact), checks=[entry])
    seal = sign_local(predicate, SIGNER)
    assert seal.envelope is not None
    return SealCase(artifact, predicate, seal.envelope, (seal.to_intoto_jsonl() + "\n").encode(), {})


def test_envelope_encoding_slack_is_accepted_but_signed_bytes_are_identical() -> None:
    """INV-T9 evidence: concrete one-byte file flips the verifier still ACCEPTS.

    Each is a non-issue for the stated claim: the decoded signed bytes (PAE) and
    the signature bytes are unchanged. Only unsigned framing or hints change.
    """
    case = _canonical_case()
    text = case.line.decode()
    flips: list[tuple[str, bytes]] = []

    # (a) the trailing newline becomes another whitespace byte that strip() drops.
    b = bytearray(case.line)
    b[-1] ^= 0x2A  # "\n" (0x0a) -> " " (0x20)
    flips.append(("trailing newline -> space", bytes(b)))

    # (b) the keyid member name is renamed, so the (unsigned) keyid hint vanishes.
    b = bytearray(case.line)
    b[text.index('"keyid"') + 1] ^= 0x01  # "keyid" -> "jeyid"
    flips.append(("keyid member renamed", bytes(b)))

    for label, line in flips:
        assert line != case.line
        out = verify_line(line, artifact=case.artifact, case=case)
        assert out.accepted, f"{label}: {out.describe()}"
        signed, sig = _signed_bytes_of(line)
        assert signed == case.envelope.signing_bytes(), label
        assert sig == case.envelope.signatures[0].sig, label


_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _flip_ignored_trailing_bit(line: bytes, b64_text: str) -> bytes:
    """Change the last data char before "=" padding by its lowest 6-bit value bit,
    which a lenient decoder discards (so the decoded bytes would be identical)."""
    assert b64_text.endswith("=")
    text = line.decode()
    pos = text.index(b64_text) + len(b64_text.rstrip("=")) - 1
    b = bytearray(line)
    b[pos] = ord(_B64_ALPHABET[_B64_ALPHABET.index(chr(b[pos])) ^ 0b000001])
    return bytes(b)


def test_non_canonical_base64_trailing_bits_are_now_refused() -> None:
    """INV-J7 fix: base64 with non-zero discarded bits used to verify (same bytes);
    canonical-only decoding now refuses it, in the payload and in the signature."""
    case = _canonical_case()
    sig_line = _flip_ignored_trailing_bit(case.line, b64(case.envelope.signatures[0].sig))
    out = verify_line(sig_line, artifact=case.artifact, case=case)
    assert not out.accepted and isinstance(out.error, VCRError), out.describe()
    payload_b64 = b64(case.envelope.payload)
    if payload_b64.endswith("="):
        payload_line = _flip_ignored_trailing_bit(case.line, payload_b64)
        out = verify_line(payload_line, artifact=case.artifact, case=case)
        assert not out.accepted and isinstance(out.error, VCRError), out.describe()


# INV-T10: re-serialization of the envelope -----------------------------------


@st.composite
def _reserialized(draw: st.DrawFn, value: object) -> str:
    ws = st.text(alphabet=" \t", max_size=3)
    if isinstance(value, dict):
        items = list(value.items())
        random.Random(draw(st.integers(0, 2**32))).shuffle(items)
        parts = [
            draw(ws) + json.dumps(k) + draw(ws) + ":" + draw(ws) + draw(_reserialized(v)) + draw(ws)
            for k, v in items
        ]
        return "{" + ",".join(parts) + "}"
    if isinstance(value, list):
        return "[" + ",".join(draw(ws) + draw(_reserialized(v)) + draw(ws) for v in value) + "]"
    return json.dumps(value, ensure_ascii=draw(st.booleans()))


@given(seal_cases(), st.data())
def test_envelope_key_order_and_inline_whitespace_do_not_change_the_verdict(
    case: SealCase, data: st.DataObject
) -> None:
    text = data.draw(_reserialized(case.envelope_dict), label="reserialized envelope")
    out = verify_line((text + "\n").encode(), artifact=case.artifact, case=case)
    assert out.accepted, out.describe()


def test_newline_whitespace_breaks_jsonl_framing_and_is_refused() -> None:
    """INV-T10 boundary: a pretty-printed (multi-line) envelope is not JSONL.

    The verifier reads exactly the first line, so indentation with newlines is
    refused even though the signed bytes are unchanged. That is the .intoto.jsonl
    framing, not a signature property; recorded, not treated as a break.
    """
    case = _canonical_case()
    pretty = json.dumps(case.envelope_dict, indent=2).encode()
    out = verify_line(pretty, artifact=case.artifact, case=case)
    assert not out.accepted and isinstance(out.error, ValueError)


# INV-T11: untrusted envelopes never escape as unhandled exceptions -----------

_json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=8),
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=6), inner, max_size=3),
    max_leaves=8,
)


@st.composite
def _hostile_envelopes(draw: st.DrawFn) -> bytes:
    case_payload = draw(st.one_of(st.binary(max_size=64), _json_values.map(lambda v: json.dumps(v).encode())))
    d: dict[str, object] = {
        "payload": draw(st.one_of(st.just(b64(case_payload)), _json_values)),
        "payloadType": draw(st.one_of(st.just(PAYLOAD_TYPE), _json_values)),
        "signatures": draw(
            st.one_of(
                st.just([{"sig": b64(SIGNER.sign(pae(PAYLOAD_TYPE, case_payload)).sig)}]),
                _json_values,
                st.lists(
                    st.dictionaries(st.sampled_from(["sig", "keyid", "cert"]), _json_values), max_size=2
                ),
            )
        ),
    }
    for k in draw(st.sets(st.sampled_from(list(d)))):
        del d[k]
    return (json.dumps(d) + "\n").encode()


@given(_hostile_envelopes())
def test_hostile_envelope_is_refused_with_a_cli_handled_error(line: bytes) -> None:
    out = verify_line(line, artifact=b"x")
    assert not out.accepted
    if out.error is not None:
        assert isinstance(out.error, CLI_HANDLED), repr(out.error)


def test_signature_class_is_frozen() -> None:
    # Guard for the helpers above: they assume one signature per T1 seal.
    case = _canonical_case()
    assert len(case.envelope.signatures) == 1
    assert isinstance(case.envelope.signatures[0], Signature)


# INV-T12: the CLI exits non-zero (no traceback) for tampered seals ------------


@pytest.mark.parametrize("how", ["payload byte", "sig byte", "payloadType", "artifact", "pretty-printed"])
def test_cli_verify_exits_nonzero_for_tampered_seals(tmp_path: Any, how: str) -> None:
    from checkseal.__main__ import main
    from checkseal.sign.local import write_public_pem

    case = _canonical_case()
    pub = tmp_path / "pub.pem"
    write_public_pem(SIGNER, str(pub))
    artifact = tmp_path / "artifact"
    artifact.write_bytes(case.artifact)
    line = case.line
    if how == "payload byte":
        p = bytearray(case.envelope.payload)
        p[len(p) // 2] ^= 0x01
        line = with_payload(case, bytes(p))
    elif how == "sig byte":
        s = bytearray(case.envelope.signatures[0].sig)
        s[0] ^= 0x80
        line = with_sig(case, bytes(s))
    elif how == "payloadType":
        line = with_payload(case, case.envelope.payload, payload_type="text/plain")
    elif how == "artifact":
        artifact.write_bytes(case.artifact + b"\n")
    else:
        line = json.dumps(case.envelope_dict, indent=2).encode()
    seal = tmp_path / "seal.intoto.jsonl"
    seal.write_bytes(line)
    argv = ["verify", str(seal), "--subject", str(artifact), "--pubkey", str(pub), "--authentic-only"]
    assert main(argv) in (1, 2)
    seal.write_bytes(case.line)
    artifact.write_bytes(case.artifact)
    assert main(argv) == 0
