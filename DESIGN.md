# CheckSeal (N1) — design decisions and report to home base

CheckSeal emits and verifies *check-receipts* for AI artifacts: which
verification checks an artifact passed, and how strongly each one binds
(enforced / advisory / observed), backed by evidence digests and, for enforced
gates, a HarnessBench proof. It rides in-toto Attestation v1 and Sigstore
keyless. It does **not** invent a competing provenance format.

This file is the report to home base: the differentiation scan, the four
architecture decisions, one CONTRACT-DELTA, the modeling flags, and the phased
plan.

## Fresh differentiation scan (verified against current sources, Aug 2026)

- **C2PA v2.3** (spec dated 2026-01-05) distinguishes embedded from
  externally-referenced assertions; externally-referenced assertion data is
  **not retrieved or validated during manifest validation**, only when an app
  specifically asks. C2PA's own attestation framework is platform/device
  attestation, not the in-toto predicate model. So embedding a CheckSeal in
  C2PA in v1 buys nothing at validation time and hard-binds us to a churning
  spec. → standalone `.intoto.jsonl` for v1; C2PA embedding is a pluggable
  backend later.
- **Sigstore keyless**: Fulcio issues a ~10-minute cert bound to an OIDC
  identity; the **Rekor inclusion timestamp** is what proves the signature
  happened while the cert was valid. This is a *not-after* bound; it does **not**
  prove *not-before*. The Verifier Contract's freshness step is sound as
  written, and the honest limit is documented in code.
- **The enriched-assertion gap** ("which prompt/policy/verification checks
  passed") on top of C2PA/SLSA remains open. That gap is CheckSeal's wedge:
  be the reference implementation of the check-assertion predicate, with the
  enforced/advisory/observed grade as the differentiator.

## The four decisions

**D1 — Build on Verification Ledger vs standalone → standalone, VL as an
optional backend later.** VL's `Record` (`payload`, `source_trust`, `durable`,
`actionable`) is a *coordination* record; a check result is an *attestation
over an artifact* (subject digest + checks + verdicts + evidence + signature).
Different nouns. "Sealing from VL records" in v1 would mean stuffing a VCR
predicate into VL's opaque `payload` and using VL as a blob store while ignoring
its one distinctive mechanism (the VL-2 promotion gate, which a seal never
uses). VL and CheckSeal align at the **provenance-typing** layer (VL `Trust` ↔
VCR `provenance.authority`; VL-3 envelope ↔ `instruction_boundary`), and that
alignment is already in the frozen VCR schema CheckSeal produces. So: standalone
store behind a narrow `SealStore` interface deliberately shaped to be satisfiable
by a VL `LedgerAdapter`. A VL-backed store (payload = check result, source_trust
= provenance.authority) is a drop-in optional extra post-skeleton, where VL's
retention (VL-4) and provenance typing (VL-1) earn their place for a real fleet.
"Do not assume it" satisfied: evaluated, declined the weld, gave it a concrete
adoption path.

**D2 — Serialization → standalone `.intoto.jsonl`, DSSE-wrapped.** in-toto's
native form; C2PA embedding reserved as a pluggable backend (Risk #2 mitigation
baked in).

**D3 — Signing → per-bundle, per the frozen profile, and the failure mode
dissolves.** One signature over one subject's checks. The "one bad digest kills
the whole seal" worry does not bite: the signature covers the Statement bytes as
claimed at seal time and stays valid; each check carries its own
`evidence.digest`, so freshness and re-execution are per-check computations the
*verifier* runs live. A stale digest fails only that check and downgrades its
`trust_floor`; it never invalidates the signature or the other checks. The
signature attests the claim; the verifier computes current truth per check.

**D4 — `/receipts` verify → CLI is the full contract, page is an honest
subset.** Step 3 (re-execute) and full step 4 (HarnessBench resolution) cannot
run in a browser. The verifier **CLI** does all six steps; the `/receipts` page
does the browser-doable subset (recompute live subject digest, check signature +
Rekor inclusion, render `trust_floor`) and states loudly what it did *not* check.
Hosted re-execution is a security hole and adoption theater; reserved for full
ambition.

## CONTRACT-DELTA FOR HOME BASE

**Verifier Contract step 4 gains a corpus-relevance check.** Resolving
`enforced_proof` is not just "does the HarnessBench record exist and cover
`check.id@config_ref`". It must confirm the HarnessBench corpus's **threat
class** matches the check's semantic class, else render **"gate unproven (corpus
mismatch)"**, never a green enforced. Rationale: HarnessBench's only shipped
corpus is ASI05 destructive-execution; an essay's rights-gate is a content
check. Pointing a rights-gate's `enforced_proof` at an ASI05 row would prove a
gate HarnessBench never tested — the exact signed-lie failure mode CheckSeal
exists to prevent. This is implemented in `hbresolve.py` and locked by
`tests/test_honesty.py`.

A name/class match is not enough on its own, and this is the sharp point: the
check's threat class is derived from `check.id`, which is producer-controlled, so
a producer can rename a check to make any corpus "cover" it. The only unforgeable
binding is a cryptographic one, so `resolve_enforced_proof` requires:

1. Declare `threat_class` on each report (defense-in-depth; the semantic class
   the corpus tests).
2. **Declare the subject config's `config_sha256` on each report** — this is a
   hard precondition, not a nicety. Resolution requires the report's
   `config_sha256` to equal the seal's `check.config_ref`, so a producer must
   exhibit a HarnessBench report that measured THIS exact config.

Until HarnessBench ships (2), **nothing resolves**: the verifier renders "gate
unproven (weak binding)" and a public enforced seal cannot pass. That is the
honest current state, and it is a concrete N2 dependency for Phase 3, not a
cosmetic note. The rename attack and the weak-binding refusal are locked by
`tests/test_propagation.py`.

## Modeling choices I own (flagged, not core-schema changes)

- **`provenance` is per check-entry**, not per predicate: the 1:1 mapping to a
  VL record ("who asserted THIS result, on what boundary"). Reduces to a single
  predicate-level authority when all entries agree.
- **`predicateType` URI** is pinned to one constant (`model.PREDICATE_TYPE`);
  confirm the exact string against home base's frozen VCR.
- **`subject.kind`** unknown-but-well-formed values parse as inert text (render
  conservatively) rather than hard-failing, since the full value set lives at
  home base.
- **Threat-class convention:** the last path segment of `check.id` names the
  check's threat class (`guard/destructive-execution` → `destructive-execution`).

## Signing tiers

T0 unsigned (ledger rows only, never public) · T1 local Ed25519 (lower tier,
offline, fully implemented + tested here) · T2 Sigstore keyless (Fulcio + Rekor;
the **only** tier valid for a public N1 seal). T2 is implemented against
sigstore-python and exercised in CI, since keyless needs an OIDC credential and
network — structurally the same built-not-executed-here split HarnessBench used
for its live tier.

## Phased plan

- **Phase 0 (done):** repo, VCR predicate model + defensive parser, canonical
  serialization, in-toto Statement, DSSE envelope, `SealStore` interface + JSONL
  store, trust_floor + E1.
- **Phase 1 (done):** producer/sealer, per-bundle signing (T1 offline; T2
  keyless implemented), N1 profile validation.
- **Phase 2 (done):** verifier CLI implementing all six contract steps,
  including step-4 corpus-relevance; conformance/honesty tests.
- **Phase 3 (in progress):** the `/receipts` client-side honest-subset verifier
  is built in JavaScript (`js/checkseal_verify.mjs`) and proven cross-language: a
  Python-signed seal verifies in the browser/Node verifier, and tamper, wrong-key,
  and malformed-payload are all caught (`node --test js/`). The T2 keyless path has
  a CLI (`seal-keyless` / `verify-keyless`) and a GitHub Actions workflow
  (`.github/workflows/seal.yml`, `id-token: write`) that mints a public seal via
  OIDC. REMAINING and gated: (i) a public *enforced* seal is blocked until N2 ships
  `config_sha256`; (ii) sealing the real essay + tool artifacts and wiring the live
  `/receipts` page + publish are outward-facing and operator-gated.
- **Phase 4 (later):** VL-backed store extra, C2PA embedding backend, hosted
  verifier, PyPI release, in-toto/C2PA community engagement.

## Reserved for v2 (inherited program decision)

The Check-Set Manifest (a signed "artifacts of kind K must carry checks {set}"
policy detecting a MISSING required check) is deferred. v1 seals its own
artifacts where the producer is controlled, so selective omission is out of
scope and "absence proves nothing" is a stated boundary. A seal extension slot
is reserved so the manifest lands later without a breaking change.

## Verification status

`cryptography` present, `sigstore` absent (T2 is CI-exercised). 32 tests pass,
including the post-review regression suite (`tests/test_propagation.py`).

CLI walking-skeleton demo, two cases:
- Against the **real shipped** `semantic-clean-room.v1.json` row *today*: the
  enforced gate renders "gate unproven (weak binding)" and VERDICT FAIL, because
  HarnessBench does not yet declare `config_sha256`. This is the honest result.
- Against an N2-ready copy of that row that declares `config_sha256`: the proof
  resolves (corpus covers the check, ees=1.0, config-sha bound), trust_floor 2,
  VERDICT PASS.

The gap between the two is exactly CONTRACT-DELTA ask (2), and it blocks a public
enforced seal until N2 ships it.

## Review

Phase 0-2 passed a specialist adversarial review (python-reviewer). Two confirmed
false-PASS bugs and several propagation gaps were fixed before this line:
the forgeable corpus-relevance bypass (now requires cryptographic config binding),
`verdict.result` and freshness now propagate to the verdict (split into
`authentic` vs `checks_passed`), the CLI stub re-executor was replaced with a real
subprocess re-executor, grade-C authority is re-enforced at verify, an EES floor
was added, and `--proof-root` path traversal was confined.
