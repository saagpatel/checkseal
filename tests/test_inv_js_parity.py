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
from hypothesis import event, example, given
from hypothesis import strategies as st

from _invariant_support import (
    OTHER_SIGNER,
    SIGNER,
    JsWorker,
    Outcome,
    SealCase,
    b64,
    envelope_line,
    mutated_statements,
    node_binary,
    raw_public_b64,
    resign,
    seal_cases,
    verify_line,
    with_payload,
    with_sig,
)
from checkseal.digest import canonical_bytes
from checkseal.dsse import b64decode_canonical, pae
from checkseal.json_utils import loads_unique_json
from checkseal.model import VCRError
from checkseal.statement import build_statement
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


# INV-J4: both base64 decoders accept exactly the same strings, same bytes ------

_b64_text = st.text(alphabet="ABCDQRwxyz0189+/= \t\n!-_", max_size=16)


@given(st.one_of(_b64_text, st.binary(max_size=12).map(b64)))
@example("YQ==")
@example("YR==")  # non-zero trailing bits: once accepted by both, now refused by both
@example("YQ")  # unpadded: once accepted by atob only
@example("Y!Q==")  # junk char: once accepted by Python only
@example("YQ===")  # excess padding: once accepted by Python only
def test_base64_decoders_accept_the_same_strings_and_bytes(js: JsWorker, text: str) -> None:
    reply = js.call(op="b64", text=text)
    try:
        py: bytes | None = b64decode_canonical(text, "t")
    except VCRError:
        py = None
    js_bytes = base64.b64decode(reply["bytes"]) if "bytes" in reply else None
    assert js_bytes == py, (text, reply)
    if py is not None:
        assert b64(py) == text  # exactly one accepted spelling per byte string


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
# Was BROKEN (xfail strict): JS ignored the keyid hint. Pinned counterexample kept.


@given(seal_cases(max_checks=1), st.sampled_from(_VARIANTS), st.text(min_size=1, max_size=4))
@example(case=MINIMAL, how="keyid changed", junk="x")
def test_js_subset_pass_implies_python_subset_pass(js: JsWorker, case: SealCase, how: str, junk: str) -> None:
    line = _variant(case, how, junk)
    js_ok, reply = js_accepts(js, line, case.artifact)
    if js_ok:
        out = verify_line(line, artifact=case.artifact, case=case)
        assert py_subset_accepts(out), f"{how}: JS PASS, Python: {out.describe()}"


def test_keyid_hint_is_checked_identically(js: JsWorker) -> None:
    """The INV-J6 pin, stated directly: keyid "x" over a valid signature is
    refused by both; an absent or null keyid is no hint, accepted by both."""
    line = _variant(MINIMAL, "keyid changed", "x")
    js_ok, reply = js_accepts(js, line, MINIMAL.artifact)
    assert not js_ok and "key id mismatch" in reply["report"]["signatureReason"], reply
    assert not verify_line(line, artifact=MINIMAL.artifact, case=MINIMAL).accepted
    for how in ("null", "absent"):
        d = MINIMAL.envelope_dict
        if how == "null":
            d["signatures"][0]["keyid"] = None
        else:
            del d["signatures"][0]["keyid"]
        assert js_accepts(js, envelope_line(d), MINIMAL.artifact)[0], how
        assert verify_line(envelope_line(d), artifact=MINIMAL.artifact, case=MINIMAL).accepted, how


# INV-J7: completeness: Python authentic implies JS subset PASS -----------------
# Was BROKEN (xfail strict): Python's lenient base64 accepted a '!' in the payload.


@given(seal_cases(max_checks=1), st.sampled_from(_VARIANTS), st.text(min_size=1, max_size=4))
@example(case=MINIMAL, how="junk char in payload base64", junk="")
def test_python_authentic_implies_js_subset_pass(js: JsWorker, case: SealCase, how: str, junk: str) -> None:
    line = _variant(case, how, junk)
    out = verify_line(line, artifact=case.artifact, case=case)
    if out.accepted:
        js_ok, reply = js_accepts(js, line, case.artifact)
        assert js_ok, f"{how}: Python PASS, JS: {reply}"


# INV-J10: on any honestly signed payload, the two subset verdicts are equal ----

_EDGES = ["none", "none", "none", "bom", "nan", "big int", "big float", "deep", "dup"]


@st.composite
def _signed_payloads(draw: st.DrawFn) -> tuple[bytes, bytes]:
    """(payload bytes, artifact): a real Statement mutated at any depth (members
    deleted, added or retyped), serialized with or without JSON-level edge cases
    (BOM, NaN, out-of-range numbers, deep nesting, a duplicate member)."""
    case = draw(seal_cases(max_checks=2))
    statement = draw(mutated_statements(build_statement(case.predicate)))
    text = json.dumps(statement, ensure_ascii=draw(st.booleans()))
    edge = draw(st.sampled_from(_EDGES))
    if edge == "bom":
        text = "﻿" + text
    elif edge in ("nan", "big int", "big float", "deep"):
        value = {"nan": "NaN", "big int": "1" + "0" * 320, "big float": "1e400"}.get(edge, "")
        if edge == "deep":
            depth = draw(st.integers(60, 70))
            value = "[" * depth + "]" * depth
        text = text[:-1] + ',"x":' + value + "}"
    elif edge == "dup":
        text = '{"_type":0,' + text[1:]
    return text.encode("utf-8"), case.artifact


_EXTRA_PREDICATE_MEMBER = MINIMAL.envelope.payload.replace(
    b'"vcr_version":"0.2"', b'"vcr_version":"0.2","x":1'
)


@given(_signed_payloads())
@example((_EXTRA_PREDICATE_MEMBER, b""))
@example((b"\xef\xbb\xbf" + MINIMAL.envelope.payload, b""))  # BOM: once a JS-only PASS
def test_signed_payload_subset_verdicts_are_equal(js: JsWorker, sample: tuple[bytes, bytes]) -> None:
    payload, artifact = sample
    line = envelope_line(resign(payload))
    js_ok, reply = js_accepts(js, line, artifact)
    assert "threw" not in reply, reply
    out = verify_line(line, artifact=artifact)
    event(f"subset verdict: {'PASS' if js_ok else 'refused'}")
    assert js_ok is py_subset_accepts(out), (payload[:300], reply, out.describe()[:300])


# INV-J8: the JS verifier returns a report, never throws ----------------------
# Was BROKEN (xfail strict): a predicate digest key "sha257" made verifySeal throw.


def _statement_with(mutate: Any) -> dict[str, Any]:
    statement = copy.deepcopy(loads_unique_json(MINIMAL.envelope.payload))
    mutate(statement)
    return statement


def _set_digest(value: Any) -> Any:
    def f(s: dict[str, Any]) -> None:
        s["predicate"]["subject"]["digest"] = value

    return f


_STATEMENT_BASE: dict[str, Any] = loads_unique_json(MINIMAL.envelope.payload)
_SHA257 = _statement_with(_set_digest({"sha257": MINIMAL.predicate.subject.digest}))


@given(
    st.one_of(mutated_statements(_STATEMENT_BASE), st.builds(dict), st.lists(st.none(), max_size=2)),
    st.booleans(),
    st.booleans(),
)
@example(_SHA257, True, True)  # one flipped byte ("6" -> "7") of a real seal's payload
@example(_SHA257, False, True)
def test_js_verifier_always_returns_a_report(
    js: JsWorker, statement: Any, signed: bool, artifact: bool
) -> None:
    payload = json.dumps(statement).encode()
    pt = MINIMAL.envelope.payload_type
    sig = {"sig": b64(SIGNER.sign(pae(pt, payload)).sig)} if signed else {"sig": "AA=="}
    envelope = {"payload": b64(payload), "payloadType": pt, "signatures": [sig]}
    reply = js.verify(json.dumps(envelope), b"x" if artifact else b"", PUB)
    assert "threw" not in reply, reply
    report = reply["report"]
    assert isinstance(report["authenticSubset"], bool)
    if report.get("malformed"):
        assert report["authenticSubset"] is False and report["entries"] == []


_any_json = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=6) | st.sampled_from(["AA==", "", "!"]),
    lambda inner: (
        st.lists(inner, max_size=3)
        | st.dictionaries(
            st.sampled_from(["payload", "payloadType", "signatures", "sig", "keyid", "x"]), inner
        )
    ),
    max_leaves=8,
)


@given(_any_json)
def test_js_verifier_returns_a_report_for_any_envelope_shape(js: JsWorker, envelope: Any) -> None:
    reply = js.verify(json.dumps(envelope), b"x", PUB)
    assert "threw" not in reply and "parseError" not in reply, reply
    assert reply["report"]["authenticSubset"] is False


# INV-J9: the JS trust floor stays in {0, 1, 2} with a defined label ----------
# Was BROKEN (xfail strict): "constructor" resolved to Object.prototype members.

_PROTO_NAMES = ["constructor", "__proto__", "toString", "valueOf", "hasOwnProperty"]


@given(
    st.one_of(st.text(max_size=12), st.sampled_from(_PROTO_NAMES + ["enforced", "advisory"])),
    st.one_of(st.text(max_size=12), st.sampled_from(_PROTO_NAMES + ["A", "B"])),
)
@example("constructor", "A")
@example("__proto__", "toString")
def test_js_trust_floor_is_always_0_1_or_2(js: JsWorker, enforced: str, grade: str) -> None:
    reply = js.call(op="floor", entry={"verdict": {"enforced": enforced}, "evidence": {"grade": grade}})
    bind = {"enforced": 2, "advisory": 1, "observed": 0}.get(enforced, 0)
    grade_rank = {"A": 2, "B": 1, "C": 0}.get(grade, 0)
    assert reply["floor"] == str(min(bind, grade_rank)), (enforced, grade, reply)
    assert reply["label"] is not None


# INV-J11: strict JSON acceptance parity --------------------------------------

_MAX_DOUBLE_INT = str(int(1.7976931348623157e308))
_JSON_INNER = [
    "1",
    "NaN",
    "Infinity",
    "-Infinity",
    "1e308",
    "1e309",
    "-1e400",
    "1" + "0" * 308,
    "1" + "0" * 309,
    _MAX_DOUBLE_INT,
    str(int(_MAX_DOUBLE_INT) + 2**970),  # rounds up to 2**1024: Infinity in JS
    "1.7976931348623157e308",
    "1.7976931348623159e308",
    '"s"',
    '{"a":1,"a":2}',
    "[]",
    "{}",
    "-0",
    "0.0",
]


@st.composite
def _json_edge_texts(draw: st.DrawFn) -> str:
    depth = draw(st.integers(0, 70))
    text = "[" * depth + draw(st.sampled_from(_JSON_INNER)) + "]" * depth
    return draw(st.sampled_from(["", " ", "﻿", "\n"])) + text


@given(_json_edge_texts())
@example("[" * 64 + "]" * 64)
@example("[" * 65 + "]" * 65)
@example("1e400")
def test_python_and_js_strict_json_accept_the_same_texts(js: JsWorker, text: str) -> None:
    try:
        loads_unique_json(text)
        py_ok = True
    except (ValueError, RecursionError):
        py_ok = False
    assert js.call(op="unique", text=text)["ok"] is py_ok, text[:200]
