"""CheckSeal: emit and verify check-receipts for AI artifacts.

A CheckSeal asserts WHICH verification checks an artifact passed AND how strongly
each one binds (enforced / advisory / observed), backed by evidence digests and,
for enforced gates, a HarnessBench proof. It rides in-toto Attestation v1 and
Sigstore keyless; it does not invent a competing provenance format.

Public surface (the parts likely to be imported):
"""

from __future__ import annotations

from .dsse import Envelope, Signature
from .model import (
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
    VCRError,
)
from .operantj import entry_from_vcr_v01, ingest_operant_j_receipt
from .profile import validate_n1_profile
from .seal import Seal, assemble, sign_keyless, sign_local
from .statement import build_statement, parse_statement, statement_bytes
from .store import CheckResult, JsonlSealStore, SealStore, T0Record
from .trust import render_trust_floor, trust_floor
from .verify import VerificationReport, verify_keyless_seal, verify_local_seal

__all__ = [
    "Authority",
    "Check",
    "CheckEntry",
    "CheckKind",
    "CheckResult",
    "Enforced",
    "EnforcedProof",
    "Envelope",
    "Evidence",
    "EvidenceKind",
    "Grade",
    "JsonlSealStore",
    "Predicate",
    "Provenance",
    "Result",
    "Runner",
    "Runtime",
    "Seal",
    "SealStore",
    "Signature",
    "Subject",
    "SubjectKind",
    "T0Record",
    "VCRError",
    "VerificationReport",
    "assemble",
    "build_statement",
    "entry_from_vcr_v01",
    "ingest_operant_j_receipt",
    "parse_statement",
    "render_trust_floor",
    "sign_keyless",
    "sign_local",
    "statement_bytes",
    "trust_floor",
    "validate_n1_profile",
    "verify_keyless_seal",
    "verify_local_seal",
]

__version__ = "0.1.0"
