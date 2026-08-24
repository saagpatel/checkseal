"""The agent-tooling profile v0.1: seals over skills and MCP servers.

A subject-class profile layered on N1 (an agent-tooling seal must also satisfy
``validate_n1_profile``). It constrains values only; no core VCR field changes.
Normative spec: ``docs/profile-agent-tooling.md``.

The stance rendered as rules:

* Identity is bytes (digest of the canonical bundle manifest or of the archive
  as distributed), never a registry name.
* Review-time scan checks may claim ``observed`` or ``advisory``, never
  ``enforced`` — no HarnessBench corpus covers scan-gate threat classes, so an
  ``enforced_proof`` could not resolve; the profile refuses the over-claim at
  the producer rather than letting the verifier render it unproven later.
* The ``runtime/`` check namespace is reserved for runtime-behavior receipts
  (profile v0.2); v0.1 rejects it so half-specified runtime claims cannot ship.
* Scan results are ``pass``/``fail``/``error`` only. A scanner failure is
  ``error``, never a silent ``skip`` or ``n/a``: a check that was not attempted
  is simply absent, and absence is not claimable.
"""

from __future__ import annotations

from .model import CheckKind, Enforced, Grade, Predicate, Result, SubjectKind, VCRError
from .profile import validate_n1_profile

PROFILE_VERSION = "0.1"

#: Subject artifact is the canonical content manifest of a directory bundle
#: (recompute with :func:`checkseal.bundle.canonical_manifest`).
BUNDLE_MANIFEST_MEDIA_TYPE = "application/vnd.checkseal.bundle-manifest+json"
#: An MCP Bundle (.mcpb) archive; the subject is the zip bytes as distributed.
MCPB_MEDIA_TYPE = "application/vnd.mcpb+zip"

_SCAN_NS = "scan/"
_RESERVED_NS = ("runtime/",)
_SUBJECT_KINDS = (
    SubjectKind.SKILL_BUNDLE.value,
    SubjectKind.MCP_SERVER.value,
    SubjectKind.ARTIFACT.value,  # pre-delta records; still valid
)


def validate_agent_tooling_profile(predicate: Predicate, *, public: bool) -> None:
    """Raise VCRError if the predicate violates the agent-tooling profile.

    Runs producer-side before signing (same posture as the N1 profile: a seal
    that over-claims must be unmintable, not merely renderable as suspect).
    """
    subject = predicate.subject
    if subject.kind not in _SUBJECT_KINDS:
        raise VCRError(
            "agent-tooling: subject.kind must be 'skill_bundle' or 'mcp_server' "
            "(first-class kinds, schema delta signed off 2026-08-24; 'artifact' "
            f"accepted for records minted before the delta); got {subject.kind!r}"
        )
    if subject.media_type is None:
        raise VCRError(
            "agent-tooling: subject.mediaType is mandatory — it tells the verifier how "
            f"to recompute identity ({BUNDLE_MANIFEST_MEDIA_TYPE!r} means the canonical "
            "bundle manifest; anything else means the raw bytes of the named artifact)"
        )

    for entry in predicate.checks:
        cid = entry.check.id

        for ns in _RESERVED_NS:
            if cid.startswith(ns):
                raise VCRError(
                    f"agent-tooling: check {cid!r} uses the reserved {ns!r} namespace; "
                    "runtime-behavior receipts are not defined in profile "
                    f"v{PROFILE_VERSION} and may not be emitted"
                )
        if not cid.startswith(_SCAN_NS):
            raise VCRError(
                f"agent-tooling: check {cid!r} is outside the {_SCAN_NS!r} namespace; "
                f"profile v{PROFILE_VERSION} covers review-time scan checks only"
            )

        # Equality (never identity) comparisons throughout: a producer building
        # dataclasses straight from scanner JSON may carry plain strings where
        # the enums are expected, and StrEnum equality covers both spellings.
        if entry.check.kind != CheckKind.REVIEW:
            raise VCRError(
                f"agent-tooling: check {cid!r} must be kind 'review'; got {str(entry.check.kind)!r}"
            )
        if entry.check.config_ref is None:
            raise VCRError(
                f"agent-tooling: check {cid!r} has no config_ref; the scan-configuration "
                "digest is mandatory (it pins which ruleset produced this verdict)"
            )
        if entry.verdict.enforced == Enforced.ENFORCED:
            raise VCRError(
                f"agent-tooling: check {cid!r} claims 'enforced'; scan checks are "
                "'observed' or 'advisory' — no corpus exists that could prove a "
                "scan gate, so the claim would be unprovable by construction"
            )
        if entry.verdict.result not in (Result.PASS, Result.FAIL, Result.ERROR):
            raise VCRError(
                f"agent-tooling: check {cid!r} has result {str(entry.verdict.result)!r}; "
                "scan results are 'pass', 'fail', or 'error' — 'skip' and 'n/a' would "
                "claim a check that was not attempted (it must be absent instead), and "
                "'over_blocked' is ground-truth-relative (N2-profile only)"
            )
        if entry.evidence.grade not in (Grade.A, Grade.B):
            raise VCRError(
                f"agent-tooling: check {cid!r} has grade {str(entry.evidence.grade)}; "
                "scan evidence must be grade A (deterministic re-scan) or B (immutable "
                "report digest) — human attestation cannot back a scan verdict"
            )

    validate_n1_profile(predicate, public=public)
