# VCR check-receipts and EU AI Act Article 12: a shape mapping

**This is a schema note, not legal advice.** It maps an open receipt format onto the *shape* of
Article 12's record-keeping expectations. It makes no compliance claim, certifies nothing, and
creates no obligation. If you need Article 12 compliance, you need counsel, not a seal format.

## Why this note exists

Article 12 of the EU AI Act (record-keeping, in force for enforcement since 2026-08-02) asks
high-risk AI systems for automatic recording of events over the system's lifetime, sufficient
traceability to reconstruct operation, and records that can be trusted after the fact. Analysts
note there is no mature, agreed provenance standard for AI agents. The observation here is
narrow: a signed check-receipt format designed for honesty already has the *shape* regulators
describe — so an open format can satisfy that shape without a proprietary compliance product.

## The mapping

| Article 12 expectation (shape) | VCR / CheckSeal mechanism |
|---|---|
| Automatic recording of events | Each receipt is a machine-emitted record of one check run: `check` (what ran, which version, which configuration by digest) + `runtime` (`ran_at`, `runner`, `duration_ms`, `env_digest`) |
| Traceability to a specific system state | `subject.digest` pins the exact bytes examined; `check.config_ref` pins the exact ruleset; `runtime.env_digest` pins the environment — reconstruction is by digest, not by narrative |
| Reliability of the record after the fact | DSSE-wrapped in-toto Statement: the signature covers the exact payload bytes; any alteration invalidates it (tamper evidence) |
| Attribution of the record | Signing tiers: public seals are Sigstore keyless (T2) — the certificate binds the record to an identity and issuer; a signature proves *who recorded*, never *truth* |
| Time anchoring / retention | T2 seals carry Rekor transparency-log inclusion with `integratedTime`; a verifier can enforce a freshness bound that **fails closed** when the log time is unreadable |
| Distinguishing recorded outcome from asserted authority | The verifier splits `authentic` (signed, digest-bound, fresh) from `checks_passed` (the verdicts themselves); `trust_floor` is displayed, never a bare claim |

## What the format deliberately does not claim

The mapping is honest only with its boundaries attached:

- A receipt asserts **presence with evidence, never absence**. It records that named checks ran
  and what they returned; it cannot record that "all required events" were captured
  (missing-check detection is deferred to a later schema version and stated as a boundary).
- The receipt format records *check events*, not the full operational event stream of a deployed
  system. It is a shape for the record-keeping layer, not a logging system.
- Nothing here interprets Article 12's legal scope, applicability, or sufficiency. The claim is
  strictly: *the structural properties regulators describe — automatic, traceable,
  tamper-evident, attributable, time-anchored records — are the same properties this open format
  was already built to have.*

## References

- VCR v0.2 predicate shape: `src/checkseal/model.py`; profiles: `docs/profile-agent-tooling.md`,
  `src/checkseal/profile.py`.
- Envelope and signing: in-toto Attestation v1 + DSSE; Sigstore keyless (Fulcio + Rekor) for
  public seals.
- EU AI Act, Article 12 (Regulation (EU) 2024/1689) — consult the regulation text and counsel
  directly; this note intentionally paraphrases only its shape.
