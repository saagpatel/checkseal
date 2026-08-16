# Worked example: sealing the Field Manual

A CheckSeal over a **real artifact with real evidence**, end to end. The subject
is the operator's vendored *Operator Field Manual* source; the checks are its
actual publication rights-gate and provenance ledger, bound to the artifact's
exact bytes. Nothing here is fabricated.

## What the seal asserts

- **subject**: `field-manual` (sha256 `3f755a52…`, the vendored source).
- **review/rights-gate** (advisory, grade B): publication authorized — MIT,
  operator consent recorded, no revocation. Evidence = the digest of
  `field-manual-publication-rights.json` (schema `field-manual-publication-rights.v2`),
  whose own `artifact.sha256` equals this subject, so the record provably concerns
  this artifact.
- **review/provenance-ledger** (advisory, grade B): evidence = the
  `fable-provenance-rights-ledger` digest the rights record cites.

Both checks are **advisory** on purpose: they are human/review attestations, not
mechanically-enforced gates. So the seal claims no `enforced` verdict and needs
no HarnessBench proof — it renders `trust_floor: surfaced`, never a bare
"enforced". This is the honesty rule in practice: assert only what the evidence
supports.

## Verify it yourself

```bash
PYTHONPATH=src python -m checkseal verify examples/artifacts/field-manual.intoto.jsonl \
  --subject /path/to/session-42-field-manual.md \
  --pubkey examples/artifacts/field-manual.verify-key.pem
```

## Tiers

This demo is **T1** (local Ed25519 — the committed `.verify-key.pem` is the
matching public key). A *public* seal on saagarpatel.dev must be **T2** (Sigstore
keyless), produced by `.github/workflows/seal.yml` so the signature is
identity-bound with a Rekor transparency-log entry. Regenerate with
`examples/seal_field_manual.py`.

---

# Worked example: the first ENFORCED seal (harness config)

The Field Manual seal is advisory; this one is **enforced**, and it is the reason
the CONTRACT-DELTA mattered. The subject is a harness config (HarnessBench's
`semantic-clean-room` subject), and the single check asserts its
destructive-execution guard is mechanically **enforced** — backed by the actual
HarnessBench report that measured it.

## What makes the claim honest

The claim binds cryptographically, not by name. Three hashes are the same value:

- **subject digest** = sha256 of the config's canonical content manifest
  (`harnessbench-semantic-clean-room.config-manifest.json`, listing `settings.json`,
  `CLAUDE.md`, and `hooks/guard.py`).
- **check.config_ref** = the same `config_sha256`.
- the vendored HarnessBench report's **`config_sha256`** = the same value.

So the seal cannot cite a report of some *other* config: the verifier resolves the
`enforced_proof` only when `config_sha256 == check.config_ref` (see
`src/checkseal/hbresolve.py`). A producer who renames the check cannot borrow this
report. Before HarnessBench declared `config_sha256`, this seal could not resolve
at all and rendered "gate unproven (weak binding)".

The check is **Grade B** (the immutable report is the evidence) with a rerunnable
`config_ref`, which is exactly what invariant E1 requires to back an `enforced`
verdict without re-executing the guard at verify time. It renders
`trust_floor: surfaced` — enforced binding, immutable-artifact evidence — and the
proof line shows the resolution.

## Verify it yourself

```bash
PYTHONPATH=src python -m checkseal verify examples/artifacts/harness-config.intoto.jsonl \
  --subject examples/artifacts/harnessbench-semantic-clean-room.config-manifest.json \
  --pubkey examples/artifacts/harness-config.verify-key.pem
```

Run it from the repo root so the report's repo-relative `enforced_proof.uri`
resolves. Regenerate with `examples/seal_harness_config.py`.
