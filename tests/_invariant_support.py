"""Shared strategies, deterministic test keys, and verifier drivers for the
invariant property tests (tests/test_inv_*.py).

Keys are derived from fixed labels so failures replay; they are test fixtures
only and never leave memory. Nothing here touches the network or Sigstore.
"""

from __future__ import annotations

import atexit
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import strategies as st

from checkseal.digest import sha256_hex
from checkseal.dsse import PAYLOAD_TYPE, Envelope, pae
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
    SubjectKind,
    Verdict,
)
from checkseal.seal import sign_local
from checkseal.sign.local import LocalKeySigner, LocalKeyVerifier
from checkseal.verify import VerificationReport, verify_local_seal

REPO = Path(__file__).resolve().parent.parent


def test_signer(label: str) -> LocalKeySigner:
    """A deterministic Ed25519 test key (never written to disk)."""
    seed = hashlib.sha256(b"checkseal-invariant-test-key:" + label.encode()).digest()
    return LocalKeySigner(Ed25519PrivateKey.from_private_bytes(seed))


test_signer.__test__ = False  # type: ignore[attr-defined]

SIGNER = test_signer("primary")
OTHER_SIGNER = test_signer("other")
VERIFIER: LocalKeyVerifier = SIGNER.verifier()


def raw_public_b64(signer: LocalKeySigner) -> str:
    raw = signer.public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.standard_b64encode(raw).decode("ascii")


# --------------------------------------------------------------------------
# Strategies
# --------------------------------------------------------------------------

HB_CORPUS = "asi05-destructive-execution"
HB_CLASS = "destructive-execution"

sha_hex = st.binary(max_size=16).map(sha256_hex)
short_text = st.text(max_size=24)
check_ids = st.from_regex(r"[a-z0-9]{1,6}(/[a-z0-9-]{1,8}){0,3}", fullmatch=True)


@st.composite
def subjects(draw: st.DrawFn, artifact: bytes) -> Subject:
    kind = draw(st.one_of(st.sampled_from([k.value for k in SubjectKind]), short_text))
    # The agent-tooling profile has its own rules; keep those subjects out of the
    # generic tamper corpus (they are covered by tests/test_profile_agent_tooling.py).
    if kind in (SubjectKind.SKILL_BUNDLE.value, SubjectKind.MCP_SERVER.value):
        kind = SubjectKind.ARTIFACT.value
    media = draw(st.one_of(st.none(), st.sampled_from(["text/plain", "application/json"])))
    return Subject(
        kind=kind,
        digest=sha256_hex(artifact),
        name=draw(st.text(max_size=48)),
        media_type=media,
    )


def _hb_report(config_ref: str) -> bytes:
    report = {
        "schema": "harnessbench-report/v1",
        "corpus": HB_CORPUS,
        "ees": 1.0,
        "verdicts": {"enforced": 10, "advised": 0, "permitted": 1, "errors": 0},
        "n": 11,
        "config_sha256": config_ref,
    }
    return json.dumps(report, sort_keys=True).encode()


@st.composite
def authentic_entries(draw: st.DrawFn) -> tuple[CheckEntry, dict[str, bytes]]:
    """An entry that a correct verifier must trust, plus any proof bytes it needs.

    Covers advisory/observed at every grade the N1 profile allows, and enforced
    Grade-A entries backed by a resolving in-memory HarnessBench report.
    """
    proofs: dict[str, bytes] = {}
    runtime = Runtime(
        ran_at=draw(short_text),
        runner=draw(st.sampled_from(list(Runner))),
        duration_ms=draw(st.one_of(st.none(), st.integers(min_value=0, max_value=2**53))),
        env_digest=draw(st.one_of(st.none(), sha_hex)),
    )
    if draw(st.booleans()):
        config_ref = draw(sha_hex)
        raw = _hb_report(config_ref)
        uri = f"mem://{sha256_hex(raw)}"
        proofs[uri] = raw
        cid = draw(st.from_regex(r"[a-z0-9]{1,6}", fullmatch=True)) + "/" + HB_CLASS
        entry = CheckEntry(
            check=Check(id=cid, kind=CheckKind.GUARD, version=draw(short_text), config_ref=config_ref),
            verdict=Verdict(
                result=draw(st.sampled_from(list(Result))),
                enforced=Enforced.ENFORCED,
                enforced_proof=EnforcedProof(sha256=sha256_hex(raw), uri=uri),
            ),
            evidence=Evidence(kind=EvidenceKind.EXIT_CODE, grade=Grade.A, digest=draw(sha_hex)),
            runtime=runtime,
            provenance=Provenance(authority=draw(st.sampled_from(list(Authority)))),
        )
        return entry, proofs
    grade = draw(st.sampled_from(list(Grade)))
    authority = Authority.OPERATOR if grade is Grade.C else draw(st.sampled_from(list(Authority)))
    entry = CheckEntry(
        check=Check(
            id=draw(check_ids),
            kind=draw(st.sampled_from(list(CheckKind))),
            version=draw(short_text),
            config_ref=draw(st.one_of(st.none(), sha_hex)),
        ),
        verdict=Verdict(
            result=draw(st.sampled_from(list(Result))),
            enforced=draw(st.sampled_from([Enforced.ADVISORY, Enforced.OBSERVED])),
        ),
        evidence=Evidence(
            kind=draw(st.sampled_from(list(EvidenceKind))),
            grade=grade,
            digest=draw(sha_hex),
            uri=draw(st.one_of(st.none(), short_text)),
        ),
        runtime=runtime,
        provenance=Provenance(authority=authority),
    )
    return entry, proofs


@dataclass(frozen=True)
class SealCase:
    """A freshly sealed, untampered T1 seal and everything needed to verify it."""

    artifact: bytes
    predicate: Predicate
    envelope: Envelope
    line: bytes  # the exact .intoto.jsonl bytes the CLI writes
    proofs: dict[str, bytes]

    @property
    def envelope_dict(self) -> dict[str, Any]:
        return self.envelope.to_jsonable()

    def loader(self, uri: str) -> bytes:
        return self.proofs[uri]


@st.composite
def seal_cases(draw: st.DrawFn, max_checks: int = 3) -> SealCase:
    artifact = draw(st.binary(max_size=64))
    subject = draw(subjects(artifact))
    pairs = draw(st.lists(authentic_entries(), min_size=1, max_size=max_checks))
    proofs: dict[str, bytes] = {}
    for _, p in pairs:
        proofs.update(p)
    predicate = Predicate(subject=subject, checks=[e for e, _ in pairs])
    seal = sign_local(predicate, SIGNER, public=False)
    assert seal.envelope is not None
    line = (seal.to_intoto_jsonl() + "\n").encode("utf-8")
    return SealCase(artifact, predicate, seal.envelope, line, proofs)


# --------------------------------------------------------------------------
# Python verifier driver
# --------------------------------------------------------------------------

_TMP = tempfile.mkdtemp(prefix="checkseal-inv-")
atexit.register(shutil.rmtree, _TMP, ignore_errors=True)
_SEAL_PATH = os.path.join(_TMP, "seal.intoto.jsonl")

# Exception families the CLI turns into a clean non-zero exit (see __main__.main).
CLI_HANDLED = (OSError, ValueError, RuntimeError)


@dataclass(frozen=True)
class Outcome:
    accepted: bool
    report: VerificationReport | None
    error: BaseException | None

    def describe(self) -> str:
        if self.error is not None:
            return f"raised {type(self.error).__name__}: {self.error}"
        assert self.report is not None
        return self.report.render(authentic_only=True)


def verify_line(
    line: bytes,
    *,
    artifact: bytes,
    verifier: LocalKeyVerifier = VERIFIER,
    case: SealCase | None = None,
    reexecutor: Any = None,
    loader: Any = None,
) -> Outcome:
    """Run the real Python verifier on raw seal-file bytes.

    "Accepted" means the CLI verdict with --authentic-only would be PASS: the
    seal is signed, digest-bound, and every entry is trusted. Any exception is a
    refusal (the CLI exits non-zero); callers separately check its type.
    """
    with open(_SEAL_PATH, "wb") as fh:
        fh.write(line)
    if case is not None:
        reexecutor = reexecutor or (lambda _e: True)
        loader = loader or case.loader
    try:
        report = verify_local_seal(
            _SEAL_PATH, verifier, subject_bytes=artifact, reexecutor=reexecutor, loader=loader
        )
    except Exception as exc:  # noqa: BLE001 - every exception is a refusal; type checked by callers
        return Outcome(False, None, exc)
    return Outcome(report.passes(authentic_only=True), report, None)


def envelope_line(d: dict[str, Any]) -> bytes:
    """Serialize an envelope dict the way the sealer does (one canonical line)."""
    return (json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode("ascii")


def with_payload(case: SealCase, payload: bytes, *, payload_type: str = PAYLOAD_TYPE) -> bytes:
    """Replace the payload (keeping the original signature) and serialize."""
    d = case.envelope_dict
    d["payload"] = b64(payload)
    d["payloadType"] = payload_type
    return envelope_line(d)


def with_sig(case: SealCase, sig: bytes) -> bytes:
    d = case.envelope_dict
    d["signatures"][0]["sig"] = b64(sig)
    return envelope_line(d)


def resign(payload: bytes, signer: LocalKeySigner = SIGNER) -> dict[str, Any]:
    """Envelope over arbitrary payload bytes, honestly signed by a test key."""
    return Envelope(payload, PAYLOAD_TYPE, [signer.sign(pae(PAYLOAD_TYPE, payload))]).to_jsonable()


# --------------------------------------------------------------------------
# JavaScript verifier driver (node, one long-lived worker per session)
# --------------------------------------------------------------------------

JS_HARNESS = Path(__file__).resolve().parent / "js_harness.mjs"


class JsWorker:
    def __init__(self, node: str) -> None:
        self._proc = subprocess.Popen(
            [node, str(JS_HARNESS)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            cwd=str(REPO),
        )

    def call(self, **request: Any) -> dict[str, Any]:
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(json.dumps(request) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            raise RuntimeError("js harness exited")
        result: dict[str, Any] = json.loads(line)
        return result

    def verify(self, envelope_text: str, artifact: bytes, pubkey_b64: str) -> dict[str, Any]:
        return self.call(op="verify", envelope=envelope_text, artifact=b64(artifact), pubkey=pubkey_b64)

    def close(self) -> None:
        if self._proc.stdin is not None:
            self._proc.stdin.close()
        self._proc.wait(timeout=10)


def node_binary() -> str | None:
    return shutil.which("node")


# --------------------------------------------------------------------------
# Statement fuzzing and the schema oracle (INV-S4, INV-J8, INV-J10)
# --------------------------------------------------------------------------

SCHEMA_PATH = REPO / "schemas" / "vcr-predicate-0.2.schema.json"


def _predicate_validator() -> Any:
    """Draft 2020-12 validator for the vendored predicate schema.

    JSON Schema patterns are ECMA-262 regexes, where ``$`` matches only at the
    end of input. The jsonschema library evaluates them with Python's re.search,
    whose ``$`` also matches before a trailing newline, so the oracle swaps in
    ``\\Z`` to keep ECMA semantics (``"a\\n"`` is not a valid check.id).
    """
    import re

    from jsonschema import Draft202012Validator, validators
    from jsonschema.exceptions import ValidationError

    def ecma_pattern(validator: Any, pattern: str, instance: Any, _schema: Any) -> Any:
        if validator.is_type(instance, "string") and not re.search(pattern.replace("$", r"\Z"), instance):
            yield ValidationError(f"{instance!r} does not match {pattern!r}")

    cls = validators.extend(Draft202012Validator, {"pattern": ecma_pattern})
    return cls(json.loads(SCHEMA_PATH.read_text()))


PREDICATE_VALIDATOR = _predicate_validator()


def statement_oracle(statement: Any) -> bool:
    """Independent acceptance rule for a decoded Statement: the in-toto Statement
    v1 layer as statement.py documents it, plus the vendored predicate schema."""
    from checkseal.model import PREDICATE_TYPE, STATEMENT_TYPE

    if not isinstance(statement, dict):
        return False
    if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE:
        return False
    predicate = statement.get("predicate")
    if not PREDICATE_VALIDATOR.is_valid(predicate):
        return False
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict):
        return False
    s0 = subjects[0]
    if not isinstance(s0.get("digest"), dict):
        return False
    psub = predicate["subject"]
    return bool(s0.get("name") == psub["name"] and s0["digest"].get("sha256") == psub["digest"]["sha256"])


_HEX = "0123456789abcdef"
_leaf_values = st.one_of(
    st.none(),
    st.booleans(),
    st.sampled_from([0, 1, -1, 2**53, 1.0, 1.5, -0.0, 1e300]),
    st.integers(-5, 5),
    st.sampled_from(
        [
            "",
            "0.2",
            "a",
            "a\n",
            "Bad Id",
            "pass",
            "fail",
            "advisory",
            "enforced",
            "observed",
            "constructor",
            "__proto__",
            "A",
            "B",
            "C",
            "review",
            "guard",
            "ci",
            "operator",
            "log-digest",
            "0" * 64,
            "A" * 64,
            "0" * 63,
            "0" * 64 + "\n",
            "n" * 257,
        ]
    ),
    st.text(max_size=6),
)
_json_values: st.SearchStrategy[Any] = st.recursive(
    _leaf_values,
    lambda inner: st.lists(inner, max_size=2) | st.dictionaries(st.text(max_size=4), inner, max_size=2),
    max_leaves=4,
)
_member_names = st.sampled_from(
    [
        "sha256",
        "sha512",
        "kind",
        "name",
        "digest",
        "mediaType",
        "id",
        "version",
        "config_ref",
        "result",
        "enforced",
        "enforced_proof",
        "uri",
        "grade",
        "inline",
        "ran_at",
        "runner",
        "duration_ms",
        "env_digest",
        "authority",
        "instruction_boundary",
        "vcr_version",
        "extra",
        "__proto__",
    ]
)


def _paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    out = [prefix]
    if isinstance(value, dict):
        for k, v in value.items():
            out += _paths(v, prefix + (k,))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out += _paths(v, prefix + (i,))
    return out


@st.composite
def mutated_statements(draw: st.DrawFn, base: dict[str, Any]) -> dict[str, Any]:
    """A Statement with 0-3 structural mutations at any depth: a member deleted,
    an extra member added, or a value replaced with an arbitrary JSON value."""
    import copy

    statement = copy.deepcopy(base)
    for _ in range(draw(st.integers(0, 3))):
        path = draw(st.sampled_from(_paths(statement)))
        parent: Any = statement
        for p in path[:-1]:
            parent = parent[p]
        target = parent[path[-1]] if path else statement
        how = draw(st.sampled_from(["delete", "add", "replace"]))
        if how == "add" and isinstance(target, dict):
            target[draw(_member_names)] = draw(_json_values)
        elif how == "delete" and path and isinstance(parent, dict):
            del parent[path[-1]]
        elif how == "delete" and path and isinstance(parent, list):
            parent.pop(path[-1])
        elif path:
            parent[path[-1]] = draw(_json_values)
    return statement
