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
from typing import Any, Literal, cast

# FLAG: confirm the exact predicateType URI against home base's frozen VCR.
PREDICATE_TYPE = "https://saagarpatel.dev/vcr/v0.2"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
VCR_VERSION = "0.2"

_SHA256_LEN = 64


class SubjectKind(StrEnum):
    ARTIFACT = "artifact"
    HARNESS_CONFIG = "harness_config"
    # Signed off by home base 2026-08-24 (additive delta) for the agent-tooling
    # profile; mirrors vcr-core's schema enum.
    SKILL_BUNDLE = "skill_bundle"
    MCP_SERVER = "mcp_server"
    # FLAG: home base's VCR may enumerate more subject kinds. Unknown kinds
    # parse as a warning, not a hard error, so a home-base addition does not
    # break the verifier. See parse_subject_kind.


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

    @property
    def is_ok(self) -> bool:
        return self not in (Result.FAIL, Result.ERROR, Result.OVER_BLOCKED)


ResultState = Literal["pass", "fail", "over_blocked", "error", "skip", "n/a"]
EnforcementState = Literal["enforced", "advisory", "observed"]


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
    assert isinstance(v, str)
    v = v.strip().lower()
    _require(
        len(v) == _SHA256_LEN and all(c in "0123456789abcdef" for c in v),
        f"{ctx}: not a lowercase 64-hex sha256",
    )
    return cast(str, v)


_SHA256_CHARS = frozenset("0123456789abcdef")


def _sha256_exact(v: Any, ctx: str) -> str:
    """Schema form of a digest: exactly 64 lowercase hex chars, no normalization."""
    _require(
        isinstance(v, str) and len(v) == _SHA256_LEN and all(c in _SHA256_CHARS for c in v),
        f"{ctx}: not a lowercase 64-hex sha256",
    )
    return cast(str, v)


def _members(
    d: Any, ctx: str, *, required: tuple[str, ...], optional: tuple[str, ...] = ()
) -> dict[str, Any]:
    """Enforce the schema's ``required`` list and ``additionalProperties: false``."""
    _require(isinstance(d, dict), f"{ctx}: must be an object")
    assert isinstance(d, dict)
    missing = [k for k in required if k not in d]
    _require(not missing, f"{ctx}: missing required member(s) {missing}")
    extra = sorted(set(d) - set(required) - set(optional))
    _require(not extra, f"{ctx}: unknown member(s) {extra}")
    return d


def _digest_set(d: Any, ctx: str) -> str:
    """``$defs/sha256``: an object with exactly one member, ``sha256``."""
    return _sha256_exact(_members(d, ctx, required=("sha256",))["sha256"], ctx)


def _str(v: Any, ctx: str, *, max_len: int | None = None) -> str:
    _require(isinstance(v, str), f"{ctx}: must be a string")
    assert isinstance(v, str)
    if max_len is not None:
        _require(len(v) <= max_len, f"{ctx}: exceeds {max_len} chars")
    return v


def parse_subject_kind(v: Any) -> str:
    """Known kinds map to the enum; unknown strings pass through as inert text.

    Rationale: subject.kind is a core VCR field whose full value set lives at
    home base. An unknown-but-well-formed kind is not a reason to refuse a seal;
    it is a reason to render conservatively. Non-strings are rejected.
    """
    kind = _str(v, "subject.kind")
    try:
        return SubjectKind(kind).value
    except ValueError:
        return kind


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
        missing = [k for k in ("kind", "digest", "name") if k not in d]
        _require(not missing, f"subject: missing required member(s) {missing}")
        # The schema's subject object sets no additionalProperties, so unknown
        # members are allowed here (and only here).
        mt = _str(d["mediaType"], "subject.mediaType") if "mediaType" in d else None
        return Subject(
            kind=parse_subject_kind(d["kind"]),
            digest=_digest_set(d["digest"], "subject.digest"),
            name=_str(d["name"], "subject.name", max_len=256),
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
        d = _members(d, "check", required=("id", "kind", "version"), optional=("config_ref",))
        cid = _str(d["id"], "check.id")
        _require(_valid_check_id(cid), f"check.id: {cid!r} violates ^[a-z0-9]+(/[a-z0-9-]+)*$")
        config_ref = _digest_set(d["config_ref"], "check.config_ref") if "config_ref" in d else None
        return Check(
            id=cid,
            kind=CheckKind(_str(d["kind"], "check.kind")),
            version=_str(d["version"], "check.version"),
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
        d = _members(d, "enforced_proof", required=("sha256", "uri"))
        return EnforcedProof(
            sha256=_sha256_exact(d["sha256"], "enforced_proof"),
            uri=_str(d["uri"], "enforced_proof.uri"),
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
        d = _members(d, "verdict", required=("result", "enforced"), optional=("enforced_proof",))
        ep = EnforcedProof.from_jsonable(d["enforced_proof"]) if "enforced_proof" in d else None
        return Verdict(
            result=Result(_str(d["result"], "verdict.result")),
            enforced=Enforced(_str(d["enforced"], "verdict.enforced")),
            enforced_proof=ep,
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
        inline = isinstance(d, dict) and "inline" in d
        _require(not inline, "evidence.inline is forbidden under the N1 profile")
        d = _members(d, "evidence", required=("kind", "grade", "digest"), optional=("uri",))
        return Evidence(
            kind=EvidenceKind(_str(d["kind"], "evidence.kind")),
            grade=Grade(_str(d["grade"], "evidence.grade")),
            digest=_digest_set(d["digest"], "evidence.digest"),
            uri=_str(d["uri"], "evidence.uri") if "uri" in d else None,
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
        d = _members(d, "runtime", required=("ran_at", "runner"), optional=("duration_ms", "env_digest"))
        dur: int | None = None
        if "duration_ms" in d:
            raw = d["duration_ms"]
            # JSON Schema "integer" is a number with no fractional part, so 5.0 qualifies.
            integral = (isinstance(raw, int) and not isinstance(raw, bool)) or (
                isinstance(raw, float) and raw.is_integer()
            )
            _require(integral and raw >= 0, "runtime.duration_ms: non-negative int")
            dur = int(raw)
        env_digest = _digest_set(d["env_digest"], "runtime.env_digest") if "env_digest" in d else None
        return Runtime(
            ran_at=_str(d["ran_at"], "runtime.ran_at"),
            runner=Runner(_str(d["runner"], "runtime.runner")),
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
        d = _members(d, "provenance", required=("authority", "instruction_boundary"))
        ib = _members(d["instruction_boundary"], "provenance.instruction_boundary", required=("kind",))
        return Provenance(
            authority=Authority(_str(d["authority"], "provenance.authority")),
            instruction_boundary_kind=_str(ib["kind"], "instruction_boundary.kind"),
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
        d = _members(d, "check entry", required=("check", "verdict", "evidence", "runtime", "provenance"))
        return CheckEntry(
            check=Check.from_jsonable(d["check"]),
            verdict=Verdict.from_jsonable(d["verdict"]),
            evidence=Evidence.from_jsonable(d["evidence"]),
            runtime=Runtime.from_jsonable(d["runtime"]),
            provenance=Provenance.from_jsonable(d["provenance"]),
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
        d = _members(d, "predicate", required=("vcr_version", "subject", "checks"))
        checks = d["checks"]
        _require(isinstance(checks, list) and len(checks) >= 1, "predicate.checks: non-empty list")
        version = _str(d["vcr_version"], "vcr_version")
        _require(version == VCR_VERSION, f"vcr_version must be {VCR_VERSION!r}")
        return Predicate(
            subject=Subject.from_jsonable(d["subject"]),
            checks=[CheckEntry.from_jsonable(c) for c in checks],
            vcr_version=version,
        )
