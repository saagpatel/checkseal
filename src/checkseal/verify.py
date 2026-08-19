"""The Verifier Contract. This is what CheckSeal owns.

A verification is valid only if the verifier:
  1. RECOMPUTES the live subject digest and compares to subject.digest.
  2. Checks Rekor inclusion for a not-after freshness bound (T2 only; Rekor
     bounds staleness, it does not prove not-before).
  3. For enforced + Grade-A, RE-EXECUTES with config_ref and confirms. For
     Grade-B, treats the check<->evidence binding as producer-trusted.
  4. Resolves enforced_proof against HarnessBench (with corpus-relevance), or
     marks "gate unproven".
  5. Renders trust_floor, never a bare ``enforced``.
  6. Treats ALL VCR content as untrusted (defensive parsing; nothing from the
     seal is ever executed; only an injected re-executor runs).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field

from .digest import sha256_file, sha256_hex
from .dsse import PAYLOAD_TYPE, Envelope, pae
from .hbresolve import ReportLoader, default_report_loader, resolve_enforced_proof
from .model import Authority, CheckEntry, Enforced, Grade, Predicate, Result, VCRError
from .sign.base import Identity, SignatureVerifier, SigningTier
from .statement import parse_statement
from .trust import check_invariant_e1, render_trust_floor, trust_floor

# Runs the check's gate against config_ref and returns True iff it still enforces.
ReExecutor = Callable[[CheckEntry], bool]


@dataclass
class EntryFinding:
    check_id: str
    result: str
    enforced: str
    trust_floor: int
    trust_floor_label: str
    reexecution: str  # confirmed | not-applicable | not-run | FAILED
    enforced_proof: str
    trusted: bool  # authenticity: E1 + re-exec + proof + grade-C authority hold
    result_ok: bool  # the check's own verdict did not report a failure

    @property
    def ok(self) -> bool:
        return self.trusted and self.result_ok


@dataclass
class VerificationReport:
    tier: str
    subject_digest_ok: bool
    subject_reason: str
    signature_ok: bool
    signature_reason: str
    identity: str | None
    freshness_reason: str
    freshness_ok: bool = True
    entries: list[EntryFinding] = field(default_factory=list)

    @property
    def authentic(self) -> bool:
        """The seal's assertions are trustworthy: signed, digest-bound, fresh, verified."""
        return (
            self.subject_digest_ok
            and self.signature_ok
            and self.freshness_ok
            and all(e.trusted for e in self.entries)
        )

    @property
    def checks_passed(self) -> bool:
        """Every check reported a passing result (no fail/error/over_blocked)."""
        return all(e.result_ok for e in self.entries)

    @property
    def ok(self) -> bool:
        return self.authentic and self.checks_passed

    def passes(self, *, authentic_only: bool = False) -> bool:
        """The verifier's exit decision.

        ``authentic_only`` gates on authenticity alone (signature + subject digest +
        freshness + trusted entries) and NOT on whether the checks passed. That is the
        honest verdict for an OBSERVED sitting that faithfully records failures: the seal
        is genuine and binds these exact results, even though the results include fails.
        Without it, ``ok`` also requires every check to pass, the right default for a gate.
        """
        return self.authentic if authentic_only else self.ok

    def render(self, *, authentic_only: bool = False) -> str:
        lines = [
            f"seal tier: {self.tier}",
            f"[1] subject digest: {'OK' if self.subject_digest_ok else 'MISMATCH'} - {self.subject_reason}",
            f"    signature:      {'OK' if self.signature_ok else 'INVALID'} - {self.signature_reason}"
            + (f" ({self.identity})" if self.identity else ""),
            f"[2] freshness:      {'OK' if self.freshness_ok else 'FAILED'} - {self.freshness_reason}",
        ]
        for e in self.entries:
            flag = "ok" if e.ok else ("check FAILED" if not e.result_ok else "UNTRUSTED")
            lines.append(
                f"  - {e.check_id}: result={e.result} floor={e.trust_floor} ({e.trust_floor_label}) [{flag}]"
            )
            lines.append(f"      [3] re-exec: {e.reexecution}")
            lines.append(f"      [4] proof:   {e.enforced_proof}")
        lines.append(
            f"authentic: {'yes' if self.authentic else 'NO'}  |  "
            f"checks passed: {'yes' if self.checks_passed else 'NO'}"
        )
        mode = " (authenticity only; check results not gated)" if authentic_only else ""
        lines.append(f"VERDICT: {'PASS' if self.passes(authentic_only=authentic_only) else 'FAIL'}{mode}")
        return "\n".join(lines)


def load_envelope(seal_path: str) -> Envelope:
    """Load a T0/T1 .intoto.jsonl seal into a DSSE envelope."""
    with open(seal_path, encoding="utf-8") as fh:
        first = fh.readline().strip()
    return Envelope.from_jsonable(json.loads(first))


def _predicate_from_envelope(env: Envelope) -> Predicate:
    if env.payload_type != PAYLOAD_TYPE:
        raise VCRError(f"unexpected DSSE payloadType {env.payload_type!r}")
    statement = json.loads(env.payload.decode("utf-8"))
    return parse_statement(statement)  # step 6: untrusted, validated


def _check_subject(
    predicate: Predicate, *, subject_path: str | None, subject_bytes: bytes | None
) -> tuple[bool, str]:
    if subject_path is None and subject_bytes is None:
        return (
            False,
            "no live subject provided; a seal verified in isolation proves a past state, not the served one",
        )
    live = sha256_file(subject_path) if subject_path is not None else sha256_hex(subject_bytes or b"")
    if live == predicate.subject.digest:
        return True, f"live digest matches ({live[:12]}...)"
    return False, f"live digest {live[:12]}... != sealed {predicate.subject.digest[:12]}..."


def _verify_entries(
    predicate: Predicate,
    *,
    reexecutor: ReExecutor | None,
    loader: ReportLoader,
    attested_authority: bool,
) -> list[EntryFinding]:
    findings: list[EntryFinding] = []
    for entry in predicate.checks:
        trusted = True
        result_ok = entry.verdict.result not in (Result.FAIL, Result.ERROR, Result.OVER_BLOCKED)

        # E1 is a hard structural invariant.
        try:
            check_invariant_e1(entry)
        except VCRError as exc:
            findings.append(_fail_finding(entry, f"E1 violated: {exc}"))
            continue

        # Step 3: re-execution for enforced + Grade-A.
        reexec = "not-applicable"
        if entry.verdict.enforced is Enforced.ENFORCED and entry.evidence.grade is Grade.A:
            if reexecutor is None:
                reexec = "not-run (no re-executor supplied; run the CLI with --reexec)"
                trusted = False
            else:
                try:
                    reexec = "confirmed" if reexecutor(entry) else "FAILED"
                except Exception as exc:  # a re-executor error is a failed confirmation
                    reexec = f"FAILED ({exc})"
                if reexec != "confirmed":
                    trusted = False
        elif entry.verdict.enforced is Enforced.ENFORCED and entry.evidence.grade is Grade.B:
            reexec = "producer-trusted (Grade-B immutable artifact; check<->evidence binding not re-run)"

        # Step 4: resolve enforced_proof or render gate unproven.
        if entry.verdict.enforced_proof is not None:
            res = resolve_enforced_proof(entry, entry.verdict.enforced_proof, loader=loader)
            proof = res.reason
            if not res.resolved:
                trusted = False
        elif entry.verdict.enforced is Enforced.ENFORCED:
            proof = "gate unproven: enforced verdict with no enforced_proof"
            trusted = False
        else:
            proof = "n/a (not an enforced verdict)"

        # Grade C on a public/attested seal needs operator attestation to stand.
        if entry.evidence.grade is Grade.C:
            if entry.provenance.authority is not Authority.OPERATOR:
                proof += " | grade-C evidence requires operator authority (profile rule)"
                trusted = False
            if not attested_authority:
                proof += " | grade-C on a non-identity-attested seal"

        findings.append(
            EntryFinding(
                check_id=entry.check.id,
                result=entry.verdict.result.value,
                enforced=entry.verdict.enforced.value,
                trust_floor=trust_floor(entry),
                trust_floor_label=render_trust_floor(entry),
                reexecution=reexec,
                enforced_proof=proof,
                trusted=trusted,
                result_ok=result_ok,
            )
        )
    return findings


def _fail_finding(entry: CheckEntry, reason: str) -> EntryFinding:
    return EntryFinding(
        check_id=entry.check.id,
        result=entry.verdict.result.value,
        enforced=entry.verdict.enforced.value,
        trust_floor=trust_floor(entry),
        trust_floor_label=render_trust_floor(entry),
        reexecution="not-run",
        enforced_proof=reason,
        trusted=False,
        result_ok=entry.verdict.result not in (Result.FAIL, Result.ERROR, Result.OVER_BLOCKED),
    )


def verify_local_seal(
    seal_path: str,
    sig_verifier: SignatureVerifier,
    *,
    subject_path: str | None = None,
    subject_bytes: bytes | None = None,
    reexecutor: ReExecutor | None = None,
    loader: ReportLoader = default_report_loader,
) -> VerificationReport:
    """Verify a T0/T1 .intoto.jsonl seal. Step 2 (Rekor) is N/A for local tiers."""
    env = load_envelope(seal_path)
    predicate = _predicate_from_envelope(env)

    subject_ok, subject_reason = _check_subject(
        predicate, subject_path=subject_path, subject_bytes=subject_bytes
    )

    sig_ok, sig_reason, identity = _verify_signature_local(env, sig_verifier)

    entries = _verify_entries(
        predicate,
        reexecutor=reexecutor,
        loader=loader,
        attested_authority=identity.attested_authority if identity else False,
    )

    return VerificationReport(
        tier=(identity.tier.value if identity else "T1"),
        subject_digest_ok=subject_ok,
        subject_reason=subject_reason,
        signature_ok=sig_ok,
        signature_reason=sig_reason,
        identity=(identity.subject if identity else None),
        freshness_reason="n/a: local tier has no transparency log; public N1 seals must be T2",
        entries=entries,
    )


def _verify_signature_local(
    env: Envelope, sig_verifier: SignatureVerifier
) -> tuple[bool, str, Identity | None]:
    data = pae(env.payload_type, env.payload)
    last_err = "no signatures"
    for sig in env.signatures:
        try:
            identity = sig_verifier.verify(data, sig)
            return True, "Ed25519 signature valid over DSSE PAE", identity
        except VCRError as exc:
            last_err = str(exc)
    return False, last_err, None


def verify_keyless_seal(
    bundle_json: str,
    *,
    expected_identity: str,
    expected_issuer: str,
    subject_path: str | None = None,
    subject_bytes: bytes | None = None,
    reexecutor: ReExecutor | None = None,
    loader: ReportLoader = default_report_loader,
    max_age_seconds: int | None = None,
    now: float | None = None,
) -> VerificationReport:
    """Verify a T2 Sigstore-bundle seal, including Rekor inclusion (step 2).

    Requires the keyless extra. Rekor inclusion is verified inside sigstore; the
    freshness (not-after) policy is applied here against the bundle's log time.
    """
    from .sign.keyless import verify_bundle_keyless

    payload, identity = verify_bundle_keyless(
        bundle_json, expected_identity=expected_identity, expected_issuer=expected_issuer
    )
    statement = json.loads(payload.decode("utf-8"))
    predicate = parse_statement(statement)

    subject_ok, subject_reason = _check_subject(
        predicate, subject_path=subject_path, subject_bytes=subject_bytes
    )
    freshness_ok, freshness_reason = _freshness(bundle_json, max_age_seconds=max_age_seconds, now=now)

    entries = _verify_entries(predicate, reexecutor=reexecutor, loader=loader, attested_authority=True)
    return VerificationReport(
        tier=SigningTier.T2.value,
        subject_digest_ok=subject_ok,
        subject_reason=subject_reason,
        signature_ok=True,
        signature_reason="Sigstore keyless verified (cert chain + Rekor inclusion)",
        identity=identity.subject,
        freshness_reason=freshness_reason,
        freshness_ok=freshness_ok,
        entries=entries,
    )


def _freshness(bundle_json: str, *, max_age_seconds: int | None, now: float | None) -> tuple[bool, str]:
    """Return (ok, reason). A requested bound that cannot be evaluated fails closed."""
    if max_age_seconds is None:
        return True, "Rekor inclusion verified; no freshness bound requested"
    try:
        bundle = json.loads(bundle_json)
        # Rekor integratedTime lives in the bundle's verification material.
        tlog = bundle.get("verificationMaterial", {}).get("tlogEntries", [{}])
        integrated = int(tlog[0].get("integratedTime", 0))
    except (json.JSONDecodeError, KeyError, IndexError, ValueError, TypeError):
        return False, "freshness bound requested but Rekor integratedTime is unreadable (fail closed)"
    if integrated <= 0:
        return False, "freshness bound requested but Rekor integratedTime is absent (fail closed)"
    import time as _time

    current = now if now is not None else _time.time()
    age = current - integrated
    if age <= max_age_seconds:
        return (
            True,
            f"fresh: signed {int(age)}s ago, within {max_age_seconds}s (not-after bound; not-before unprovable)",
        )
    return False, f"STALE: signed {int(age)}s ago, exceeds {max_age_seconds}s bound"
