"""VCR v0.2 predicate: the record shape CheckSeal produces and consumes.

CheckSeal CONSUMES the VCR core schema from home base and MUST NOT change core
fields (names, enum values). This module mirrors VCR v0.2 as handed to N1. Two
things are pinned to a single constant/comment so a correction against home
base's canonical schema is a one-line change, both marked ``# FLAG``.

Serialization is written explicitly (no reflection) on purpose: this is the
byte-exact contract a signature covers, so key casing and field omission are
spelled out rather than inferred.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# FLAG: confirm the exact predicateType URI against home base's frozen VCR.
PREDICATE_TYPE = "https://saagarpatel.dev/vcr/v0.2"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
VCR_VERSION = "0.2"

_SHA256_LEN = 64


class SubjectKind(StrEnum):
    ARTIFACT = "artifact"
    HARNESS_CONFIG = "harness_config"
    # FLAG: home base's VCR may enumerate more subject kinds (the briefing text
    # was lossy here). Unknown kinds parse as a warning, not a hard error, so a
    # home-base addition does not break the verifier. See parse_subject_kind.


class CheckKind(StrEnum):
    REVIEW = "review"
    GUARD = "guard"
    HUMAN = "human"


class Result(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    OVER_BLOCKED = "over_blocked"
    ERROR = "error"
    SKIP = "skip"
    NA = "n/a"


class Enforced(StrEnum):
    """The settled three-value enforcement axis. No ``bypassed`` value."""

    ENFORCED = "enforced"
    ADVISORY = "advisory"
    OBSERVED = "observed"


class EvidenceKind(StrEnum):
    EXIT_CODE = "exit-code"
    DIFF_DIGEST = "diff-digest"
    LOG_DIGEST = "log-digest"
    TRANSCRIPT_DIGEST = "transcript-digest"
    REVIEWER_ID = "reviewer-id"


class Grade(StrEnum):
    A = "A"  # re-executable (exit-code + env_digest, diff-digest)
    B = "B"  # immutable artifact (log/transcript digest)
    C = "C"  # human attestation (reviewer-id)


class Authority(StrEnum):
    OPERATOR = "operator"
    AGENT = "agent"
    INGESTED = "ingested"


class Runner(StrEnum):
    FLEET = "fleet"
    CI = "ci"
    HUMAN = "human"


class VCRError(ValueError):
    """Raised when untrusted VCR content fails structural validation."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise VCRError(msg)


def _sha256(v: Any, ctx: str) -> str:
    _require(isinstance(v, str), f"{ctx}: sha256 must be a string")
    v = v.strip().lower()
    _require(
        len(v) == _SHA256_LEN and all(c in "0123456789abcdef" for c in v),
        f"{ctx}: not a lowercase 64-hex sha256",
    )
    return v


def _str(v: Any, ctx: str, *, max_len: int | None = None) -> str:
    _require(isinstance(v, str), f"{ctx}: must be a string")
    if max_len is not None:
        _require(len(v) <= max_len, f"{ctx}: exceeds {max_len} chars")
    return v


def parse_subject_kind(v: Any) -> str:
    """Known kinds map to the enum; unknown strings pass through as inert text.

    Rationale: subject.kind is a core VCR field whose full value set lives at
    home base. An unknown-but-well-formed kind is not a reason to refuse a seal;
    it is a reason to render conservatively. Non-strings are rejected.
    """
    v = _str(v, "subject.kind")
    try:
        return SubjectKind(v).value
    except ValueError:
        return v


@dataclass(frozen=True)
class Subject:
    kind: str
    digest: str  # sha256 hex
    name: str  # <= 256, treated as inert
    media_type: str | None = None

    def to_jsonable(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": self.kind,
            "digest": {"sha256": self.digest},
            "name": self.name,
        }
        if self.media_type is not None:
            d["mediaType"] = self.media_type  # FLAG: camelCase per VCR v0.2.
        return d

    @staticmethod
    def from_jsonable(d: Any) -> Subject:
        _require(isinstance(d, dict), "subject: must be an object")
        digest = d.get("digest")
        _require(isinstance(digest, dict), "subject.digest: must be an object")
        mt = d.get("mediaType")
        if mt is not None:
            mt = _str(mt, "subject.mediaType")
        return Subject(
            kind=parse_subject_kind(d.get("kind")),
            digest=_sha256(digest.get("sha256"), "subject.digest"),
            name=_str(d.get("name"), "subject.name", max_len=256),
            media_type=mt,
        )


@dataclass(frozen=True)
class Check:
    id: str  # ^[a-z0-9]+(/[a-z0-9-]+)*$
    kind: CheckKind
    version: str
    config_ref: str | None = None  # sha256 hex of the gating config

    def to_jsonable(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "kind": self.kind.value, "version": self.version}
        if self.config_ref is not None:
            d["config_ref"] = {"sha256": self.config_ref}
        return d

    @staticmethod
    def from_jsonable(d: Any) -> Check:
        _require(isinstance(d, dict), "check: must be an object")
        cid = _str(d.get("id"), "check.id")
        _require(_valid_check_id(cid), f"check.id: {cid!r} violates ^[a-z0-9]+(/[a-z0-9-]+)*$")
        cfg = d.get("config_ref")
        config_ref = None
        if cfg is not None:
            _require(isinstance(cfg, dict), "check.config_ref: must be an object")
            config_ref = _sha256(cfg.get("sha256"), "check.config_ref")
        return Check(
            id=cid,
            kind=CheckKind(_str(d.get("kind"), "check.kind")),
            version=_str(d.get("version"), "check.version"),
            config_ref=config_ref,
        )


def _valid_check_id(cid: str) -> bool:
    import re

    return re.fullmatch(r"[a-z0-9]+(/[a-z0-9-]+)*", cid) is not None


@dataclass(frozen=True)
class EnforcedProof:
    """A pointer to a HarnessBench dataset record proving the gate is real."""

    sha256: str  # content digest of the HarnessBench report
    uri: str

    def to_jsonable(self) -> dict[str, Any]:
        return {"sha256": self.sha256, "uri": self.uri}

    @staticmethod
    def from_jsonable(d: Any) -> EnforcedProof:
        _require(isinstance(d, dict), "enforced_proof: must be an object")
        return EnforcedProof(
            sha256=_sha256(d.get("sha256"), "enforced_proof"),
            uri=_str(d.get("uri"), "enforced_proof.uri"),
        )


@dataclass(frozen=True)
class Verdict:
    result: Result
    enforced: Enforced
    enforced_proof: EnforcedProof | None = None

    def to_jsonable(self) -> dict[str, Any]:
        d: dict[str, Any] = {"result": self.result.value, "enforced": self.enforced.value}
        if self.enforced_proof is not None:
            d["enforced_proof"] = self.enforced_proof.to_jsonable()
        return d

    @staticmethod
    def from_jsonable(d: Any) -> Verdict:
        _require(isinstance(d, dict), "verdict: must be an object")
        ep = d.get("enforced_proof")
        return Verdict(
            result=Result(_str(d.get("result"), "verdict.result")),
            enforced=Enforced(_str(d.get("enforced"), "verdict.enforced")),
            enforced_proof=EnforcedProof.from_jsonable(ep) if ep is not None else None,
        )


@dataclass(frozen=True)
class Evidence:
    kind: EvidenceKind
    grade: Grade
    digest: str  # sha256 hex; MANDATORY under the N1 profile
    uri: str | None = None

    def to_jsonable(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": self.kind.value,
            "grade": self.grade.value,
            "digest": {"sha256": self.digest},
        }
        if self.uri is not None:
            d["uri"] = self.uri
        return d

    @staticmethod
    def from_jsonable(d: Any) -> Evidence:
        _require(isinstance(d, dict), "evidence: must be an object")
        _require("inline" not in d, "evidence.inline is forbidden under the N1 profile")
        digest = d.get("digest")
        _require(isinstance(digest, dict), "evidence.digest: mandatory object")
        uri = d.get("uri")
        if uri is not None:
            uri = _str(uri, "evidence.uri")
        return Evidence(
            kind=EvidenceKind(_str(d.get("kind"), "evidence.kind")),
            grade=Grade(_str(d.get("grade"), "evidence.grade")),
            digest=_sha256(digest.get("sha256"), "evidence.digest"),
            uri=uri,
        )


@dataclass(frozen=True)
class Runtime:
    ran_at: str  # ISO-8601 UTC
    runner: Runner
    duration_ms: int | None = None
    env_digest: str | None = None  # sha256 hex

    def to_jsonable(self) -> dict[str, Any]:
        d: dict[str, Any] = {"ran_at": self.ran_at, "runner": self.runner.value}
        if self.duration_ms is not None:
            d["duration_ms"] = self.duration_ms
        if self.env_digest is not None:
            d["env_digest"] = {"sha256": self.env_digest}
        return d

    @staticmethod
    def from_jsonable(d: Any) -> Runtime:
        _require(isinstance(d, dict), "runtime: must be an object")
        dur = d.get("duration_ms")
        if dur is not None:
            _require(isinstance(dur, int) and not isinstance(dur, bool), "runtime.duration_ms: int")
        env = d.get("env_digest")
        env_digest = None
        if env is not None:
            _require(isinstance(env, dict), "runtime.env_digest: object")
            env_digest = _sha256(env.get("sha256"), "runtime.env_digest")
        return Runtime(
            ran_at=_str(d.get("ran_at"), "runtime.ran_at"),
            runner=Runner(_str(d.get("runner"), "runtime.runner")),
            duration_ms=dur,
            env_digest=env_digest,
        )


@dataclass(frozen=True)
class Provenance:
    authority: Authority
    # instruction_boundary.kind is fixed vocabulary; VCR ships one value today.
    instruction_boundary_kind: str = "stored_data_not_instructions"

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "authority": self.authority.value,
            "instruction_boundary": {"kind": self.instruction_boundary_kind},
        }

    @staticmethod
    def from_jsonable(d: Any) -> Provenance:
        _require(isinstance(d, dict), "provenance: must be an object")
        ib = d.get("instruction_boundary")
        _require(isinstance(ib, dict), "provenance.instruction_boundary: object")
        return Provenance(
            authority=Authority(_str(d.get("authority"), "provenance.authority")),
            instruction_boundary_kind=_str(ib.get("kind"), "instruction_boundary.kind"),
        )


@dataclass(frozen=True)
class CheckEntry:
    """One check applied to the subject: what ran, its verdict, its evidence.

    Provenance is per-entry (who asserted THIS result, on what boundary). This
    is the 1:1 mapping to a Verification-Ledger record and reduces to a single
    predicate-level authority when every entry agrees. Modeling choice owned by
    N1 (serialization); flagged for home base in DESIGN.md.
    """

    check: Check
    verdict: Verdict
    evidence: Evidence
    runtime: Runtime
    provenance: Provenance

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "check": self.check.to_jsonable(),
            "verdict": self.verdict.to_jsonable(),
            "evidence": self.evidence.to_jsonable(),
            "runtime": self.runtime.to_jsonable(),
            "provenance": self.provenance.to_jsonable(),
        }

    @staticmethod
    def from_jsonable(d: Any) -> CheckEntry:
        _require(isinstance(d, dict), "check entry: must be an object")
        return CheckEntry(
            check=Check.from_jsonable(d.get("check")),
            verdict=Verdict.from_jsonable(d.get("verdict")),
            evidence=Evidence.from_jsonable(d.get("evidence")),
            runtime=Runtime.from_jsonable(d.get("runtime")),
            provenance=Provenance.from_jsonable(d.get("provenance")),
        )


@dataclass(frozen=True)
class Predicate:
    """A VCR v0.2 predicate: one subject, many checks."""

    subject: Subject
    checks: list[CheckEntry] = field(default_factory=list)
    vcr_version: str = VCR_VERSION

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "vcr_version": self.vcr_version,
            "subject": self.subject.to_jsonable(),
            "checks": [c.to_jsonable() for c in self.checks],
        }

    @staticmethod
    def from_jsonable(d: Any) -> Predicate:
        _require(isinstance(d, dict), "predicate: must be an object")
        checks = d.get("checks")
        _require(isinstance(checks, list) and len(checks) >= 1, "predicate.checks: non-empty list")
        return Predicate(
            subject=Subject.from_jsonable(d.get("subject")),
            checks=[CheckEntry.from_jsonable(c) for c in checks],
            vcr_version=_str(d.get("vcr_version", VCR_VERSION), "vcr_version"),
        )
