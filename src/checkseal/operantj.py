"""Ingest an OPERANT-J VCR receipt and shape it into a sealable predicate.

OPERANT-J (the judge-lane benchmark) emits Verified-Check Records through vcr-core
(VCR v0.1: ``sha256:``-prefixed digests, one ``check`` per record). CheckSeal consumes
that receipt here and re-expresses each case as a v0.2 ``CheckEntry`` so a judge sitting
can be signed and verified like any other seal. This is a one-way consumer adapter --
the judge lane's counterpart to ``hbresolve.py`` -- and it never changes vcr-core's
records.

The judge lane is honestly OBSERVED: a benchmark watches a judge produce rulings; it
enforces nothing. So every ingested check is ``enforced=observed`` with no
``enforced_proof``, kind ``review`` (a judge is a reviewer), and evidence a transcript
digest at grade B (the judge's output is an immutable transcript, not re-executable).
The adapter REFUSES any receipt that says otherwise: an ``enforced``/``advisory``
record, or an ``enforced_proof`` pointer, is the wrong lane and must not ride out under
a judge-run seal. A sealed judge sitting is therefore tamper-evident and attributable
without re-running it, while claiming exactly the enforcement it has -- none.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .digest import sha256_file
from .model import (
    Authority,
    CheckEntry,
    CheckKind,
    Enforced,
    EvidenceKind,
    Grade,
    Runner,
    Subject,
    SubjectKind,
    VCRError,
)

# The vcr-core (home-base) predicate OPERANT-J stamps on every receipt record.
VCR_V01_PREDICATE = "https://saagarpatel.dev/schema/vcr/v0.1"
_SHA256_PREFIX = "sha256:"
_SUBJECT_MEDIA_TYPE = "application/x-operant-j-vcr+jsonl"


def _bare_hex(value: Any, ctx: str) -> str:
    """vcr-core writes ``sha256:<hex>``; CheckSeal's model wants bare lowercase 64-hex.

    Validates fail-fast so a malformed receipt is refused at ingest, not at verify time.
    """
    if not isinstance(value, str):
        raise VCRError(f"{ctx}: digest must be a string")
    s = value[len(_SHA256_PREFIX) :] if value.startswith(_SHA256_PREFIX) else value
    s = s.strip().lower()
    if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
        raise VCRError(f"{ctx}: not a sha256 hex digest ({value!r})")
    return s


def _digest_of(node: Any, ctx: str) -> str:
    if not isinstance(node, dict):
        raise VCRError(f"{ctx}: expected a digest object")
    return _bare_hex(node.get("sha256"), ctx)


def entry_from_vcr_v01(record: dict, *, runner: Runner = Runner.FLEET) -> CheckEntry:
    """Translate one vcr-core v0.1 in-toto statement into a v0.2 observed CheckEntry.

    Every field is validated at ingest: the translated record is routed through the
    model's own ``CheckEntry.from_jsonable``, so a malformed receipt (bad check.id,
    missing timestamp, non-hex digest, ...) is refused HERE with VCRError rather than at
    seal time. Also raises VCRError if the record is not a vcr-core v0.1 record, or if it
    claims any enforcement (the judge lane is observed-only). An unrecognised enum value
    (e.g. an unknown verdict result) raises ValueError, matching the model's parsing
    behaviour throughout the library.
    """
    if record.get("predicateType") != VCR_V01_PREDICATE:
        raise VCRError(f"not a vcr-core v0.1 record (predicateType={record.get('predicateType')!r})")
    pred = record.get("predicate")
    if not isinstance(pred, dict):
        raise VCRError("record has no predicate object")
    check = pred.get("check") if isinstance(pred.get("check"), dict) else {}
    verdict = pred.get("verdict") if isinstance(pred.get("verdict"), dict) else {}
    evidence = pred.get("evidence") if isinstance(pred.get("evidence"), dict) else {}
    runtime = pred.get("runtime") if isinstance(pred.get("runtime"), dict) else {}

    enforced = verdict.get("enforced")
    if enforced != Enforced.OBSERVED.value:
        raise VCRError(
            f"refusing to seal check {check.get('id')!r} as a judge run: OPERANT-J is an "
            f"observed lane, but this record declares enforced={enforced!r}"
        )
    # An observed record carries no enforced_proof; a proof pointer is the wrong lane.
    if pred.get("enforced_proof") is not None or verdict.get("enforced_proof") is not None:
        raise VCRError(
            f"refusing to seal check {check.get('id')!r}: an observed judge record must not "
            "carry an enforced_proof"
        )

    # Re-express the v0.1 record as a v0.2 check entry: translate digests to bare hex and
    # fix the judge-lane profile (review / observed / transcript-digest at grade B).
    # from_jsonable then validates check.id, version, ran_at, and digests uniformly.
    check_field: dict[str, Any] = {
        "id": check.get("id"),
        "kind": CheckKind.REVIEW.value,  # a judge is a reviewer
        "version": check.get("version"),
    }
    cref = check.get("config_ref")
    if cref is not None:
        if not isinstance(cref, dict):
            raise VCRError("check.config_ref: expected a digest object")
        check_field["config_ref"] = {"sha256": _bare_hex(cref.get("sha256"), "check.config_ref")}

    entry_dict: dict[str, Any] = {
        "check": check_field,
        "verdict": {"result": verdict.get("result"), "enforced": Enforced.OBSERVED.value},
        "evidence": {
            "kind": EvidenceKind.TRANSCRIPT_DIGEST.value,  # the judge's output is a transcript
            "grade": Grade.B.value,  # an immutable transcript digest, not re-executable -> B
            "digest": {"sha256": _digest_of(evidence.get("digest"), "evidence.digest")},
        },
        "runtime": {"ran_at": runtime.get("ran_at"), "runner": runner.value},
        "provenance": {
            "authority": Authority.AGENT.value,  # the judge (an agent) asserted the ruling
            "instruction_boundary": {"kind": "stored_data_not_instructions"},
        },
    }
    return CheckEntry.from_jsonable(entry_dict)


def read_receipt(receipt_path: str | Path) -> list[dict]:
    """Parse a JSONL OPERANT-J receipt into its records; refuse an empty or malformed one.

    A bad JSON line or a non-object record raises VCRError (not a bare JSONDecodeError),
    so callers see the module's single failure type.
    """
    records: list[dict] = []
    for lineno, line in enumerate(Path(receipt_path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise VCRError(f"malformed JSON on line {lineno} of {receipt_path}: {exc}") from exc
        if not isinstance(rec, dict):
            raise VCRError(f"line {lineno} of {receipt_path} is not a JSON object")
        records.append(rec)
    if not records:
        raise VCRError(f"empty OPERANT-J receipt: {receipt_path}")
    return records


def ingest_operant_j_receipt(
    receipt_path: str | Path,
    *,
    name: str | None = None,
    runner: Runner = Runner.FLEET,
) -> tuple[Subject, list[CheckEntry]]:
    """Read an OPERANT-J VCR receipt and return (subject, observed check entries).

    The subject is the receipt file itself, so a seal over it binds these exact results:
    altering the receipt breaks the subject digest at verify time. ``name`` defaults to
    the judge identity recorded in the receipt's first record.
    """
    records = read_receipt(receipt_path)
    entries = [entry_from_vcr_v01(r, runner=runner) for r in records]
    if name is None:
        subj0 = records[0].get("subject")
        first = subj0[0] if isinstance(subj0, list) and subj0 and isinstance(subj0[0], dict) else {}
        name = str(first.get("name") or "operant-j/judge-run")
    # Route through from_jsonable so the (untrusted) name is length-checked at ingest.
    subject = Subject.from_jsonable(
        {
            "kind": SubjectKind.ARTIFACT.value,
            "name": name,
            "mediaType": _SUBJECT_MEDIA_TYPE,
            "digest": {"sha256": sha256_file(str(receipt_path))},
        }
    )
    return subject, entries
