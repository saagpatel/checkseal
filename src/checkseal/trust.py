"""Trust floor and invariant E1.

The single rule a consumer must obey: DISPLAY ``trust_floor``, never a bare
``enforced``. trust_floor is the weaker of how strongly a check binds and how
strong its evidence is, so it cannot over-claim in either dimension.
"""

from __future__ import annotations

from .model import CheckEntry, Enforced, Grade, VCRError

_BINDING_RANK: dict[Enforced, int] = {
    Enforced.ENFORCED: 2,
    Enforced.ADVISORY: 1,
    Enforced.OBSERVED: 0,
}
_GRADE_RANK: dict[Grade, int] = {Grade.A: 2, Grade.B: 1, Grade.C: 0}

_FLOOR_LABEL: dict[int, str] = {
    2: "enforced + reproducible",
    1: "surfaced",
    0: "telemetry only",
}


def binding_rank(e: Enforced) -> int:
    return _BINDING_RANK[e]


def grade_rank(g: Grade) -> int:
    return _GRADE_RANK[g]


def trust_floor(entry: CheckEntry) -> int:
    """min(binding_rank, grade_rank) in {0, 1, 2}."""
    return min(_BINDING_RANK[entry.verdict.enforced], _GRADE_RANK[entry.evidence.grade])


def render_trust_floor(entry: CheckEntry) -> str:
    """The consumer-facing string. Never returns a bare enforcement word."""
    return _FLOOR_LABEL[trust_floor(entry)]


def check_invariant_e1(entry: CheckEntry) -> None:
    """E1: an ``enforced`` verdict REQUIRES reproducible evidence.

    Grade A always qualifies. Grade B qualifies only with a rerunnable
    ``config_ref``. Grade C (human-only) can never back an ``enforced`` verdict.
    Raises VCRError on violation.
    """
    if entry.verdict.enforced is not Enforced.ENFORCED:
        return
    grade = entry.evidence.grade
    if grade is Grade.A:
        return
    if grade is Grade.B and entry.check.config_ref is not None:
        return
    raise VCRError(
        f"E1 violated for check {entry.check.id!r}: enforced requires grade A, "
        "or grade B with a rerunnable config_ref; got "
        f"grade {grade.value}" + ("" if entry.check.config_ref else " with no config_ref")
    )
