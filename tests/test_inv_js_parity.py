"""Python/JS verifier parity invariants (INV-J*), driving node from Python.

The JS verifier is the browser "honest subset" (DESIGN.md D4): it checks the
live subject digest, Statement/predicate coupling and the Ed25519 signature.
Python's matching steps are: no exception, signature_ok, subject_digest_ok
(coupling failures raise inside parse_statement).
"""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Iterator
from typing import Any

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from _invariant_support import (
    OTHER_SIGNER,
    SIGNER,
    JsWorker,
    Outcome,
    SealCase,
    b64,
    envelope_line,
    node_binary,
    raw_public_b64,
    resign,
    seal_cases,
    verify_line,
    with_payload,
    with_sig,
)
from checkseal.digest import canonical_bytes
from checkseal.dsse import pae
from checkseal.json_utils import loads_unique_json
from checkseal.trust import trust_floor

PUB = raw_public_b64(SIGNER)


@pytest.fixture(scope="module")
def js() -> Iterator[JsWorker]:
    node = node_binary()
    if node is None:
        pytest.skip("node is not installed")
    worker = JsWorker(node)
    yield worker
    worker.close()


def js_accepts(js: JsWorker, line: bytes, artifact: bytes) -> tuple[bool, dict[str, Any]]:
    reply = js.verify(line.decode("utf-8", errors="replace").splitlines()[0], artifact, PUB)
    report = reply.get("report")
    return bool(report and report.get("authenticSubset")), reply


def py_subset_accepts(out: Outcome) -> bool:
    return out.report is not None and out.report.signature_ok and out.report.subject_digest_ok


# INV-J1: Python-sealed seals verify in JS, with the same trust floors ----------


@given(seal_cases())
def test_python_sealed_seal_verifies_in_js_with_equal_trust_floors(js: JsWorker, case: SealCase) -> None:
    ok, reply = js_accepts(js, case.line, case.artifact)
    assert ok, reply
    floors = [e["trustFloor"] for e in reply["report"]["entries"]]
    assert floors == [trust_floor(e) for e in case.predicate.checks]


# INV-J2: signed-content tampers are refused by both --------------------------


@given(seal_cases(max_checks=2), st.data())
def test_signed_content_tamper_is_refused_by_both_verifiers(
    js: JsWorker, case: SealCase, data: st.DataObject
) -> None:
    how = data.draw(st.sampled_from(["payload byte", "sig byte", "artifact", "payloadType", "other key"]))
    line, artifact = case.line, case.artifact
    if how == "payload byte":
        p = bytearray(case.envelope.payload)
        p[data.draw(st.integers(0, len(p) - 1))] ^= data.draw(st.integers(1, 255))
        line = with_payload(case, bytes(p))
    elif how == "sig byte":
        s = bytearray(case.envelope.signatures[0].sig)
        s[data.draw(st.integers(0, len(s) - 1))] ^= data.draw(st.integers(1, 255))
        line = with_sig(case, bytes(s))
    elif how == "artifact":
        artifact = case.artifact + data.draw(st.binary(min_size=1, max_size=4))
    elif how == "payloadType":
        t = data.draw(st.text(max_size=20).filter(lambda x: x != case.envelope.payload_type))
        line = with_payload(case, case.envelope.payload, payload_type=t)
    else:
        line = envelope_line(resign(case.envelope.payload, OTHER_SIGNER))
    js_ok, reply = js_accepts(js, line, artifact)
    assert not js_ok, reply  # a thrown error is also a refusal here; INV-J8 covers throwing
    assert not verify_line(line, artifact=artifact, case=case).accepted


# INV-J3: PAE byte-for-byte parity --------------------------------------------


@given(st.text(max_size=40), st.binary(max_size=64))
@example("application/vnd.in-toto+json", b"")
@example("é\U0001f600", b"\x00 1 ")
def test_js_and_python_pae_are_byte_identical(js: JsWorker, payload_type: str, body: bytes) -> None:
    reply = js.call(op="pae", type=payload_type, payload=b64(body))
    assert base64.b64decode(reply["pae"]) == pae(payload_type, body)


# INV-J4: whenever both base64 decoders accept, they decode the same bytes -----

_b64_text = st.text(alphabet="ABCDQRwxyz0189+/= \t\n!-_", max_size=16)


@given(st.one_of(_b64_text, st.binary(max_size=12).map(b64)))
@example("YQ==")
@example("YR==")
def test_when_both_base64_decoders_accept_they_agree(js: JsWorker, text: str) -> None:
    reply = js.call(op="b64", text=text)
    try:
        py = base64.standard_b64decode(text)
    except ValueError:
        return
    if "bytes" in reply:
        assert base64.b64decode(reply["bytes"]) == py, (text, reply)


# INV-J5: duplicate-member detection parity -----------------------------------


@st.composite
def _object_texts(draw: st.DrawFn, depth: int = 0) -> str:
    if depth >= 3 or draw(st.integers(0, 3)) == 0:
        return draw(st.sampled_from(['"v"', "1", "[]", '"\\"}{:"']))
    if draw(st.booleans()):
        return "[" + ",".join(draw(_object_texts(depth + 1)) for _ in range(draw(st.integers(0, 2)))) + "]"
    members = []
    for k in draw(st.lists(st.sampled_from(["a", "b", "payload", "\\u0061", "a\\\\", "{"]), max_size=4)):
        ws = draw(st.sampled_from(["", " ", "\n"]))
        members.append(f'"{k}"{ws}:{ws}{draw(_object_texts(depth + 1))}')
    return "{" + ",".join(members) + "}"


@given(_object_texts())
@example('{"a":1,"\\u0061":2}')
@example('{"x":"\\"a\\":","a":1}')
def test_js_and_python_agree_on_duplicate_json_members(js: JsWorker, text: str) -> None:
    try:
        loads_unique_json(text)
        py_ok = True
    except ValueError:
        py_ok = False
    assert js.call(op="unique", text=text)["ok"] is py_ok, text


# Encoding-layer and signed-content variants used by INV-J6 / INV-J7 -----------


def _variant(case: SealCase, how: str, junk: str) -> bytes:
    d = case.envelope_dict
    if how == "keyid changed":
        d["signatures"][0]["keyid"] = junk
    elif how == "payload padding stripped":
        d["payload"] = d["payload"].rstrip("=")
    elif how == "sig padding stripped":
        d["signatures"][0]["sig"] = d["signatures"][0]["sig"].rstrip("=")
    elif how == "junk char in payload base64":
        d["payload"] = d["payload"][:4] + "!" + d["payload"][4:]
    elif how == "excess padding":
        d["signatures"][0]["sig"] += "="
    elif how == "BOM-prefixed signed payload":
        d = resign(b"\xef\xbb\xbf" + case.envelope.payload)
    elif how == "uppercase predicate digest, re-signed":
        statement = loads_unique_json(case.envelope.payload)
        statement["predicate"]["subject"]["digest"]["sha256"] = case.predicate.subject.digest.upper()
        d = resign(canonical_bytes(statement))
    return envelope_line(d)


_VARIANTS = [
    "keyid changed",
    "payload padding stripped",
    "sig padding stripped",
    "junk char in payload base64",
    "excess padding",
    "BOM-prefixed signed payload",
    "uppercase predicate digest, re-signed",
]


def _minimal_case() -> SealCase:
    from checkseal.model import Enforced, EvidenceKind, Grade, Predicate
    from checkseal.seal import sign_local
    from conftest import make_entry, make_subject

    artifact = b""
    entry = make_entry(
        check_id="a", enforced=Enforced.OBSERVED, grade=Grade.B, evidence_kind=EvidenceKind.LOG_DIGEST
    )
    predicate = Predicate(subject=make_subject(artifact, name=""), checks=[entry])
    seal = sign_local(predicate, SIGNER)
    assert seal.envelope is not None
    return SealCase(artifact, predicate, seal.envelope, (seal.to_intoto_jsonl() + "\n").encode(), {})


MINIMAL = _minimal_case()


# INV-J6: honest-subset soundness: JS PASS implies Python's subset steps pass ---


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "BROKEN INV-J6: the browser subset PASSES envelopes the Python CLI refuses. Minimal "
        'counterexample: a valid T1 seal with signatures[0].keyid set to "x" (JS ignores keyid; '
        "Python raises key id mismatch). Also: payload or sig base64 with its '=' padding stripped "
        "(atob accepts, Python raises Incorrect padding), and a signed payload with a UTF-8 BOM "
        "(TextDecoder drops it, Python json rejects it). Signed bytes are identical in every case."
    ),
)
@given(seal_cases(max_checks=1), st.sampled_from(_VARIANTS), st.text(min_size=1, max_size=4))
@example(case=MINIMAL, how="keyid changed", junk="x")
def test_js_subset_pass_implies_python_subset_pass(js: JsWorker, case: SealCase, how: str, junk: str) -> None:
    line = _variant(case, how, junk)
    js_ok, reply = js_accepts(js, line, case.artifact)
    if js_ok:
        out = verify_line(line, artifact=case.artifact, case=case)
        assert py_subset_accepts(out), f"{how}: JS PASS, Python: {out.describe()}"


# INV-J7: completeness: Python authentic implies JS subset PASS -----------------


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "BROKEN INV-J7: the Python CLI authenticates envelopes the browser subset refuses. Minimal "
        "counterexample: a valid T1 seal with one '!' inserted into the payload base64 (Python's "
        "non-strict b64decode discards it; atob throws InvalidCharacterError). Also: an extra '=' "
        "after the sig padding, and a re-signed Statement whose predicate digest is UPPERCASE hex "
        "(Python lowercases it; JS compares raw strings). No case authenticates different bytes."
    ),
)
@given(seal_cases(max_checks=1), st.sampled_from(_VARIANTS), st.text(min_size=1, max_size=4))
@example(case=MINIMAL, how="junk char in payload base64", junk="")
def test_python_authentic_implies_js_subset_pass(js: JsWorker, case: SealCase, how: str, junk: str) -> None:
    line = _variant(case, how, junk)
    out = verify_line(line, artifact=case.artifact, case=case)
    if out.accepted:
        js_ok, reply = js_accepts(js, line, case.artifact)
        assert js_ok, f"{how}: Python PASS, JS: {reply}"


# INV-J8: the JS verifier returns a failed report, never throws ---------------


def _statement_with(mutate: Any) -> dict[str, Any]:
    statement = copy.deepcopy(loads_unique_json(MINIMAL.envelope.payload))
    mutate(statement)
    return statement


def _set_digest(value: Any) -> Any:
    def f(s: dict[str, Any]) -> None:
        s["predicate"]["subject"]["digest"] = value

    return f


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "BROKEN INV-J8 (js/checkseal_verify.mjs:132-133 claims a tampered payload never throws): "
        "flip one byte of a genuine seal's payload so the predicate.subject.digest key reads "
        '"sha257" (no signature needed) and verifySeal throws TypeError: sha256.slice of '
        "undefined at js/checkseal_verify.mjs:174, whenever artifact bytes are supplied. "
        "Any missing or non-string predicate digest value does the same."
    ),
)
@given(
    st.one_of(
        st.dictionaries(
            st.sampled_from(["sha256", "sha257", "sha512"]),
            st.one_of(st.integers(), st.booleans(), st.none(), st.just("0" * 64)),
        ),
        st.builds(dict),
    )
)
@example({"sha257": MINIMAL.predicate.subject.digest})  # one flipped byte ("6" -> "7") of a real seal
def test_js_verifier_never_throws_on_untrusted_payload(js: JsWorker, digest: Any) -> None:
    payload = json.dumps(_statement_with(_set_digest(digest))).encode()
    envelope = {"payload": b64(payload), "payloadType": MINIMAL.envelope.payload_type, "signatures": []}
    reply = js.verify(json.dumps(envelope), b"x", PUB)
    assert "threw" not in reply, reply


# INV-J9: the JS trust floor stays in {0, 1, 2} for any string ----------------


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "BROKEN INV-J9: js trustFloor looks values up in plain object literals, so "
        'verdict.enforced = "constructor" (or "__proto__", "toString", ...) yields floor NaN '
        "and label undefined instead of the conservative 0. Python rejects the value at parse."
    ),
)
@given(
    st.one_of(st.text(max_size=12), st.sampled_from(["constructor", "__proto__", "toString"])),
    st.one_of(st.text(max_size=12), st.sampled_from(["valueOf", "A"])),
)
@example("constructor", "A")
def test_js_trust_floor_is_always_0_1_or_2(js: JsWorker, enforced: str, grade: str) -> None:
    reply = js.call(op="floor", entry={"verdict": {"enforced": enforced}, "evidence": {"grade": grade}})
    assert reply["floor"] in {"0", "1", "2"}, (enforced, grade, reply)
    assert reply["label"] is not None
