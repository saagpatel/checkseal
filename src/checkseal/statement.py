"""in-toto Statement v1 wrapping a VCR predicate.

The seal is an in-toto Statement: the Statement-level subject is the resource
descriptor of what is attested; the VCR predicate carries the full claim (the
same subject plus every check). We do NOT invent a competing record format; we
ride in-toto's frozen Statement shape.
"""

from __future__ import annotations

from typing import Any

from .digest import canonical_bytes
from .model import PREDICATE_TYPE, STATEMENT_TYPE, Predicate, VCRError, _require


def build_statement(predicate: Predicate) -> dict[str, Any]:
    """Assemble the in-toto Statement dict for a predicate."""
    subj = predicate.subject
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": subj.name, "digest": {"sha256": subj.digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate.to_jsonable(),
    }


def statement_bytes(predicate: Predicate) -> bytes:
    """Canonical bytes of the Statement, the DSSE payload."""
    return canonical_bytes(build_statement(predicate))


def parse_statement(d: Any) -> Predicate:
    """Validate an untrusted Statement and return its VCR predicate.

    Enforces the Statement/predicate coupling: the Statement subject must match
    the predicate subject, so a verifier cannot be shown one subject in the
    envelope and a different one in the claim.
    """
    _require(isinstance(d, dict), "statement: must be an object")
    _require(d.get("_type") == STATEMENT_TYPE, f"statement._type must be {STATEMENT_TYPE}")
    _require(
        d.get("predicateType") == PREDICATE_TYPE,
        f"statement.predicateType must be {PREDICATE_TYPE}",
    )
    predicate = Predicate.from_jsonable(d.get("predicate"))
    subjects = d.get("subject")
    _require(
        isinstance(subjects, list) and len(subjects) == 1, "statement.subject: single-item list"
    )
    s0 = subjects[0]
    _require(isinstance(s0, dict), "statement.subject[0]: object")
    dig = s0.get("digest")
    _require(isinstance(dig, dict), "statement.subject[0].digest: object")
    if s0.get("name") != predicate.subject.name or dig.get("sha256") != predicate.subject.digest:
        raise VCRError("statement subject does not match predicate subject")
    return predicate
