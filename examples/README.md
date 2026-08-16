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
