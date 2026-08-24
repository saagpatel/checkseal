"""Seal a ``skillscan-report/v1``: the review-time receipt path for agent tooling.

Contract: ``docs/skillscan-report-v1.md``. The report is UNTRUSTED input from a
scanner this library shares no code with. The subject identity is re-derived
here from the bundle bytes; a report whose subject digest cannot be reproduced
is refused, so a drifting or lying scanner yields a refusal, never a wrong
seal. The agent-tooling profile validates before anything is stored or signed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .bundle import archive_digest, canonical_manifest
from .digest import sha256_hex
from .model import (
    Authority,
    Check,
    CheckEntry,
    CheckKind,
    Enforced,
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
    VCRError,
    Verdict,
    _require,
    _sha256,
    _str,
)
from .profile_agent_tooling import BUNDLE_MANIFEST_MEDIA_TYPE

REPORT_SCHEMA = "skillscan-report/v1"

_RESULTS = {"pass": Result.PASS, "fail": Result.FAIL, "error": Result.ERROR}
_KINDS = (SubjectKind.SKILL_BUNDLE.value, SubjectKind.MCP_SERVER.value)


@dataclass(frozen=True)
class SkillscanSeed:
    """Everything derived from one report: the predicate input plus its evidence digest."""

    predicate: Predicate
    report_digest: str  # sha256 of the exact report bytes = evidence for every entry
    manifest_bytes: bytes | None  # the canonical manifest (directory-form subjects only)


def parse_report(report_bytes: bytes) -> dict:
    """Structurally validate the untrusted report JSON. Raises VCRError."""
    try:
        d = json.loads(report_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VCRError(f"skillscan report is not valid UTF-8 JSON: {exc}") from exc
    _require(isinstance(d, dict), "skillscan report: must be an object")
    schema = _str(d.get("schema"), "report.schema")
    _require(schema == REPORT_SCHEMA, f"report.schema: expected {REPORT_SCHEMA!r}, got {schema!r}")
    _str(d.get("scanner"), "report.scanner")
    _str(d.get("scanner_version"), "report.scanner_version")
    _str(d.get("ran_at"), "report.ran_at")
    _require(isinstance(d.get("subject"), dict), "report.subject: must be an object")
    ruleset = d.get("ruleset")
    _require(isinstance(ruleset, dict), "report.ruleset: must be an object")
    _sha256(ruleset.get("config_sha256"), "report.ruleset.config_sha256")
    checks = d.get("checks")
    _require(isinstance(checks, list) and len(checks) >= 1, "report.checks: non-empty list")
    for c in checks:
        _require(isinstance(c, dict), "report check: must be an object")
        _str(c.get("id"), "report check.id")
        result = _str(c.get("result"), "report check.result")
        _require(
            result in _RESULTS,
            f"report check.result: {result!r} not in pass/fail/error (skip and n/a are not emittable)",
        )
    return d


def derive_subject(report: dict, bundle_path: str | Path) -> tuple[Subject, bytes | None]:
    """Rebuild the subject from the bundle bytes and refuse a report that disagrees.

    Returns (subject, manifest_bytes) — manifest_bytes only for the directory form.
    """
    rsub = report["subject"]
    kind = _str(rsub.get("kind"), "report.subject.kind")
    _require(
        kind in _KINDS,
        f"report.subject.kind: {kind!r} not in {_KINDS}; new emissions use the first-class kinds",
    )
    name = _str(rsub.get("name"), "report.subject.name", max_len=256)
    claimed = _sha256(rsub.get("digest"), "report.subject.digest")
    media_type = _str(rsub.get("media_type"), "report.subject.media_type")

    path = Path(bundle_path)
    manifest_bytes: bytes | None = None
    if path.is_dir():
        _require(
            media_type == BUNDLE_MANIFEST_MEDIA_TYPE,
            f"directory bundle must use media_type {BUNDLE_MANIFEST_MEDIA_TYPE!r}; got {media_type!r}",
        )
        manifest_bytes, live = canonical_manifest(path)
    elif path.is_file():
        live = archive_digest(path)
    else:
        raise VCRError(f"bundle path does not exist: {path}")

    if live != claimed:
        raise VCRError(
            f"REFUSED: report claims subject digest {claimed[:12]}... but the bundle at "
            f"{path} digests to {live[:12]}...; the scanned bytes are not these bytes"
        )
    return Subject(kind=kind, digest=live, name=name, media_type=media_type), manifest_bytes


def seed_from_report(
    report_bytes: bytes,
    bundle_path: str | Path,
    *,
    authority: Authority = Authority.AGENT,
    runner: Runner = Runner.FLEET,
) -> SkillscanSeed:
    """Parse, re-derive identity, and build the profile-shaped predicate."""
    report = parse_report(report_bytes)
    subject, manifest_bytes = derive_subject(report, bundle_path)
    report_digest = sha256_hex(report_bytes)
    config_ref = _sha256(report["ruleset"]["config_sha256"], "report.ruleset.config_sha256")

    entries = [
        CheckEntry(
            check=Check(
                id=_str(c["id"], "report check.id"),
                kind=CheckKind.REVIEW,
                version=_str(report["scanner_version"], "report.scanner_version"),
                config_ref=config_ref,
            ),
            verdict=Verdict(result=_RESULTS[c["result"]], enforced=Enforced.OBSERVED),
            evidence=Evidence(kind=EvidenceKind.LOG_DIGEST, grade=Grade.B, digest=report_digest),
            runtime=Runtime(ran_at=_str(report["ran_at"], "report.ran_at"), runner=runner),
            provenance=Provenance(authority=authority),
        )
        for c in report["checks"]
    ]
    return SkillscanSeed(
        predicate=Predicate(subject=subject, checks=entries),
        report_digest=report_digest,
        manifest_bytes=manifest_bytes,
    )
