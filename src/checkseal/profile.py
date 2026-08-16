"""The N1 profile contract: extra rules a CheckSeal must satisfy.

VCR is the base schema; the N1 profile tightens it for public seals of one's own
artifacts. These run producer-side before signing, so a seal cannot be minted
that over-claims. The verifier re-checks the tier-dependent ones (see verifier).
"""

from __future__ import annotations

from .model import Authority, Enforced, Grade, Predicate, VCRError
from .trust import check_invariant_e1


def validate_n1_profile(predicate: Predicate, *, public: bool) -> None:
    """Raise VCRError if the predicate violates the N1 profile.

    Rules:
      * E1 per check (enforced needs reproducible evidence).
      * evidence.grade in {A, B}; C only when the asserting authority is operator.
      * a public seal may not carry an ``enforced`` verdict without an
        ``enforced_proof`` pointer (do not publicly claim a gate you cannot point
        at). Advisory/observed need no proof.
      * at least one check; a single subject (guaranteed by the Predicate shape).
    """
    if not predicate.checks:
        raise VCRError("N1: a seal must carry at least one check")

    for entry in predicate.checks:
        cid = entry.check.id
        check_invariant_e1(entry)

        if entry.evidence.grade is Grade.C and entry.provenance.authority is not Authority.OPERATOR:
            raise VCRError(
                f"N1: check {cid!r} has grade C evidence but authority "
                f"{entry.provenance.authority.value!r}; grade C requires operator attestation"
            )

        if (
            public
            and entry.verdict.enforced is Enforced.ENFORCED
            and entry.verdict.enforced_proof is None
        ):
            raise VCRError(
                f"N1: public seal claims check {cid!r} is enforced but carries no "
                "enforced_proof. Emit it as advisory, or attach a HarnessBench proof."
            )
