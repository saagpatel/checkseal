"""DSSE PAE and in-toto Statement invariants (INV-D*, INV-S*)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from _invariant_support import (
    SIGNER,
    envelope_line,
    mutated_statements,
    resign,
    seal_cases,
    statement_oracle,
    verify_line,
)
from checkseal.digest import canonical_bytes, sha256_hex
from checkseal.dsse import pae
from checkseal.json_utils import loads_unique_json
from checkseal.model import Predicate, VCRError
from checkseal.statement import build_statement, parse_statement, statement_bytes

# INV-D1: PAE is injective ----------------------------------------------------


def pae_decode(data: bytes) -> tuple[bytes, bytes]:
    """Strict inverse of PAE per the DSSE spec. Its existence proves injectivity:
    pae_decode(pae(t, b)) == (t, b) for all inputs means pae has a left inverse.
    """
    prefix = b"DSSEv1 "
    if not data.startswith(prefix):
        raise ValueError("prefix")
    rest = data[len(prefix) :]

    def take_len(buf: bytes) -> tuple[int, bytes]:
        sp = buf.index(b" ")
        digits = buf[:sp]
        if not digits.isdigit() or (len(digits) > 1 and digits[0:1] == b"0"):
            raise ValueError("length")
        return int(digits), buf[sp + 1 :]

    tlen, rest = take_len(rest)
    ptype, rest = rest[:tlen], rest[tlen:]
    if len(ptype) != tlen or rest[:1] != b" ":
        raise ValueError("type")
    blen, rest = take_len(rest[1:])
    if len(rest) != blen:
        raise ValueError("body")
    return ptype, rest


_confusing = st.text(alphabet="DSSEv1 0123456789\x00é", max_size=12)
_bodies = st.one_of(st.binary(max_size=32), _confusing.map(str.encode))


@given(st.one_of(st.text(max_size=40), _confusing), _bodies)
@example("", b"")
@example("1 a", b"")
@example("", b"1 a")
def test_pae_has_a_left_inverse(payload_type: str, body: bytes) -> None:
    assert pae_decode(pae(payload_type, body)) == (payload_type.encode("utf-8"), body)


_types = st.one_of(st.text(max_size=12), _confusing)


@given(_types, _bodies, _types, _bodies)
@example("a", b"1 b", "a 1", b"b")  # the classic shifted-boundary pair
@example("1", b"", "", b"1")
def test_distinct_type_body_pairs_never_share_an_encoding(t1: str, b1: bytes, t2: str, b2: bytes) -> None:
    if (t1.encode(), b1) == (t2.encode(), b2):
        assert pae(t1, b1) == pae(t2, b2)
    else:
        assert pae(t1, b1) != pae(t2, b2)


@given(st.text(max_size=40), st.binary(max_size=64))
def test_pae_matches_the_dsse_spec_layout(payload_type: str, body: bytes) -> None:
    t = payload_type.encode("utf-8")
    spec = b" ".join([b"DSSEv1", str(len(t)).encode(), t, str(len(body)).encode(), body])
    assert pae(payload_type, body) == spec


# INV-S1: Statement round trip and canonical fixed point -----------------------


@given(seal_cases())
def test_statement_round_trips_and_is_a_canonical_fixed_point(case: Any) -> None:
    raw = statement_bytes(case.predicate)
    assert raw == case.envelope.payload
    parsed = parse_statement(loads_unique_json(raw))
    assert parsed == case.predicate
    assert statement_bytes(parsed) == raw
    assert canonical_bytes(json.loads(raw)) == raw


# INV-S2: Statement/predicate subject coupling ----------------------------------


@given(
    seal_cases(max_checks=1),
    st.sampled_from(["name", "digest", "extra subject", "no subject"]),
    st.text(min_size=1, max_size=8),
)
def test_signed_statement_with_decoupled_subject_is_refused(case: Any, what: str, junk: str) -> None:
    """Even honestly signed by the trusted key, a Statement whose subject differs
    from the predicate subject must be refused."""
    statement = build_statement(case.predicate)
    if what == "name":
        statement["subject"][0]["name"] += junk
    elif what == "digest":
        statement["subject"][0]["digest"]["sha256"] = sha256_hex(junk.encode() + case.artifact)
    elif what == "extra subject":
        statement["subject"].append(copy.deepcopy(statement["subject"][0]))
    else:
        statement["subject"] = []
    line = envelope_line(resign(canonical_bytes(statement)))
    out = verify_line(line, artifact=case.artifact, case=case)
    assert not out.accepted
    assert isinstance(out.error, VCRError), out.describe()


# INV-S3: duplicate JSON members are rejected at every depth -------------------

_keys = st.sampled_from(["a", "b", "name", "sha256"])


def _spell(key: str, escaped: bool) -> str:
    return '"' + "".join(f"\\u{ord(c):04x}" for c in key) + '"' if escaped else json.dumps(key)


@st.composite
def json_texts(draw: st.DrawFn, depth: int = 0) -> tuple[str, bool]:
    """(JSON text, has_duplicate_member). Keys may be spelled with \\u escapes."""
    if depth >= 3 or draw(st.integers(0, 3)) == 0:
        return draw(st.sampled_from(["1", '"s"', "null", "[]"])), False
    if draw(st.booleans()):
        items = [draw(json_texts(depth + 1)) for _ in range(draw(st.integers(0, 3)))]
        return "[" + ",".join(t for t, _ in items) + "]", any(d for _, d in items)
    keys = draw(st.lists(_keys, max_size=4))
    members = []
    dup = len(set(keys)) != len(keys)
    for k in keys:
        value, inner = draw(json_texts(depth + 1))
        dup = dup or inner
        members.append(_spell(k, draw(st.booleans())) + ":" + value)
    return "{" + ",".join(members) + "}", dup


@given(json_texts())
@example(('{"a":1,"\\u0061":2}', True))
@example(('{"a":{"b":1,"b":2}}', True))
def test_unique_json_rejects_exactly_the_texts_with_duplicate_members(sample: tuple[str, bool]) -> None:
    text, has_dup = sample
    if has_dup:
        with pytest.raises(VCRError, match="duplicate"):
            loads_unique_json(text)
    else:
        assert loads_unique_json(text) == json.loads(text)


# INV-S4: the parser refuses schema-invalid Statements -------------------------

_VALID = json.loads((Path(__file__).parent / "fixtures" / "schema" / "valid-statement.json").read_text())

# Pinned INV-S4 counterexamples (each used to parse; the schema rejects all three).
_without_vcr_version = copy.deepcopy(_VALID)
del _without_vcr_version["predicate"]["vcr_version"]
_with_extra_predicate_member = copy.deepcopy(_VALID)
_with_extra_predicate_member["predicate"]["unsigned_looking"] = True
_with_uppercase_predicate_digest = copy.deepcopy(_VALID)
_with_uppercase_predicate_digest["predicate"]["subject"]["digest"]["sha256"] = " " + "A" * 64
_with_uppercase_predicate_digest["subject"][0]["digest"]["sha256"] = "a" * 64


def _rejected_mutations() -> list[tuple[str, Any]]:
    """Schema violations the parser does refuse (each one breaks a schema rule)."""

    def setp(path: list[Any], value: Any) -> Any:
        def f(s: dict[str, Any]) -> None:
            cur: Any = s
            for p in path[:-1]:
                cur = cur[p]
            cur[path[-1]] = value

        return f

    return [
        ("_type", setp(["_type"], "x")),
        ("predicateType", setp(["predicateType"], "x")),
        ("vcr_version 0.3", setp(["predicate", "vcr_version"], "0.3")),
        ("checks empty", setp(["predicate", "checks"], [])),
        ("check.id pattern", setp(["predicate", "checks", 0, "check", "id"], "Bad Id")),
        ("check.kind enum", setp(["predicate", "checks", 0, "check", "kind"], "x")),
        ("verdict.result enum", setp(["predicate", "checks", 0, "verdict", "result"], "ok")),
        ("verdict.enforced enum", setp(["predicate", "checks", 0, "verdict", "enforced"], "bypassed")),
        ("evidence.grade enum", setp(["predicate", "checks", 0, "evidence", "grade"], "D")),
        ("digest not hex", setp(["predicate", "subject", "digest", "sha256"], "z" * 64)),
        ("digest short", setp(["predicate", "subject", "digest", "sha256"], "a" * 63)),
        ("name too long", setp(["predicate", "subject", "name"], "n" * 257)),
        ("duration negative", setp(["predicate", "checks", 0, "runtime", "duration_ms"], -1)),
        ("duration bool", setp(["predicate", "checks", 0, "runtime", "duration_ms"], True)),
        ("runner enum", setp(["predicate", "checks", 0, "runtime", "runner"], "x")),
        ("authority enum", setp(["predicate", "checks", 0, "provenance", "authority"], "root")),
        ("evidence.inline", setp(["predicate", "checks", 0, "evidence", "inline"], "x")),
    ]


@given(st.sampled_from(_rejected_mutations()))
def test_parser_refuses_type_enum_pattern_and_range_violations(mutation: tuple[str, Any]) -> None:
    statement = copy.deepcopy(_VALID)
    mutation[1](statement)
    with pytest.raises((VCRError, ValueError)):
        parse_statement(statement)


@given(mutated_statements(_VALID))
@example(_without_vcr_version)
@example(_with_extra_predicate_member)
@example(_with_uppercase_predicate_digest)
def test_parser_accepts_a_statement_iff_the_schema_does(statement: dict[str, Any]) -> None:
    """INV-S4: parse_statement accepts exactly the Statements the vendored schema
    (plus the documented in-toto Statement rules) accepts."""
    expected = statement_oracle(statement)
    try:
        parse_statement(statement)
        accepted = True
    except ValueError:
        accepted = False
    assert accepted is expected, json.dumps(statement)


@given(seal_cases(max_checks=2).flatmap(lambda c: mutated_statements(build_statement(c.predicate))))
def test_parser_agrees_with_the_schema_on_mutated_real_statements(statement: dict[str, Any]) -> None:
    expected = statement_oracle(statement)
    try:
        parse_statement(statement)
        accepted = True
    except ValueError:
        accepted = False
    assert accepted is expected, json.dumps(statement)


def test_schema_invalid_statement_is_refused_even_when_signed() -> None:
    """INV-S4 at the verdict: a trusted-key-signed Statement without vcr_version
    used to verify authentic; it is now refused before any signature work."""
    from checkseal.model import Enforced, EvidenceKind, Grade
    from conftest import make_entry, make_subject

    artifact = b"the essay body"
    entry = make_entry(
        enforced=Enforced.ADVISORY, grade=Grade.B, evidence_kind=EvidenceKind.LOG_DIGEST, config_ref=None
    )
    statement = build_statement(Predicate(subject=make_subject(artifact), checks=[entry]))
    del statement["predicate"]["vcr_version"]
    line = envelope_line(resign(canonical_bytes(statement), SIGNER))
    out = verify_line(line, artifact=artifact)
    assert not out.accepted
    assert isinstance(out.error, VCRError) and "vcr_version" in str(out.error)
