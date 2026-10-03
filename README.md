# CheckSeal

**A check-receipt for AI artifacts: which verification checks passed, and how
strongly each one binds.**

Provenance standards tell you *who* made an artifact and that it hasn't changed
since. They do not tell you *which checks it passed and whether those checks were
mechanically enforced or merely advisory*. CheckSeal is the reference
implementation of that check-assertion predicate. It rides
[in-toto](https://in-toto.io) Attestation v1 and [Sigstore](https://sigstore.dev)
keyless; it does not invent a competing format.

The differentiator is the **enforced / advisory / observed** grade on every
check, and the honesty machinery behind it:

- **evidence is a digest, recomputed** — a verifier checks the evidence, it does
  not trust the claim.
- **an enforced grade needs a proof** — `enforced_proof` resolves to a
  [HarnessBench](https://github.com/saagpatel/harnessbench) report that
  empirically measured the gate, and the corpus's threat class must actually
  cover the check (a destructive-execution corpus cannot prove a content
  rights-gate).
- **consumers display `trust_floor`, never a bare "enforced"** — the weaker of
  how strongly a check binds and how strong its evidence is, so a seal can't
  over-claim in either dimension.
- **Sigstore + Rekor** make backdating detectable (a not-after bound; Rekor does
  not prove not-before, and CheckSeal says so).

A seal asserts **presence with evidence**. It cannot prove a check was *not* run.
That limit is stated, not hidden.

## Install

```bash
pip install checkseal            # stdlib-only core
pip install "checkseal[sign]"      # + T1 local-key signing (cryptography)
pip install "checkseal[keyless]"   # + T2 Sigstore keyless (public seals)
```

## Quickstart (T1, offline)

```bash
checkseal keygen --out key.pem --pub key.pub.pem

# after your checks run and land in a T0 store (t0.jsonl), seal one subject:
checkseal seal --store t0.jsonl --subject ./artifact --name my/artifact \
  --key key.pem --out artifact.intoto.jsonl

# verify against the live artifact (exits non-zero if the seal does not pass):
checkseal verify artifact.intoto.jsonl --subject ./artifact --pubkey key.pub.pem
```

Public seals must be **T2** (Sigstore keyless); that path runs in CI where an
OIDC credential is available.

## The Verifier Contract

A verification is valid only if the verifier (1) recomputes the live subject
digest, (2) checks Rekor inclusion for a freshness bound, (3) re-executes
enforced Grade-A checks, (4) resolves `enforced_proof` against HarnessBench with
a corpus-relevance check, (5) renders `trust_floor`, and (6) treats all sealed
content as untrusted. See [`DESIGN.md`](DESIGN.md).

## Client-side verification (`/receipts`)

`js/checkseal_verify.mjs` is the honest browser subset: it recomputes the subject
digest, checks the Statement/predicate subject coupling, verifies the Ed25519
signature over the DSSE PAE, and renders `trust_floor` — and it states loudly
what it does NOT check (re-execution, enforced_proof resolution, full Rekor
proof), which are CLI-only. A Python-signed seal verifies in this JS verifier
(`node --test js/checkseal_verify.test.mjs`), proving the format is language-agnostic.

Public T2 seals are minted in CI: `checkseal seal-keyless` plus
`.github/workflows/seal.yml` (GitHub OIDC → Fulcio → Rekor).

## Profiles

The base predicate is constrained by per-subject-class profiles. The **N1
profile** (`src/checkseal/profile.py`) governs every public seal. The
**agent-tooling profile** ([`docs/profile-agent-tooling.md`](docs/profile-agent-tooling.md))
covers seals over agent skills and MCP servers: identity is bytes (a canonical
bundle manifest or the archive as distributed), never a registry name; scan
checks may claim `observed`/`advisory`, never `enforced`; the `runtime/`
namespace is reserved for runtime-behavior receipts. A shape mapping of the
receipt format onto EU AI Act Article 12 record-keeping lives in
[`docs/article-12-mapping.md`](docs/article-12-mapping.md) (a schema note, not
legal advice).

To seal a scanner's output over your own skills/servers:
`checkseal seal-skillscan --report scan.json --bundle ./my-skill --store t0.jsonl`
— the report contract is [`docs/skillscan-report-v1.md`](docs/skillscan-report-v1.md);
the sealer recomputes the bundle's identity from bytes and refuses a report it
cannot reproduce.

## Development verification

Run from the repository root with Python 3.12+ and Node.js 22 (the CI versions).
Use a virtual environment; the JS cross-language test invokes `python3`, so
activate the environment before running Node:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev,keyless]"
# Synthetic T1 CLI smoke: temporary artifact, store and locally generated keys.
python -m pytest -q tests/test_end_to_end.py::test_cli_keygen_seal_verify
# Broader offline suite, including keyless API import guards.
python -m pytest -q
node --test js/checkseal_verify.test.mjs
python -m ruff check src tests
```

Replace the focused test node with the affected test module/case. `dev` includes
the optional Verification Ledger backend used by its fixture tests; without
that backend or the keyless extra, the corresponding tests skip. The keyless
API guards only inspect imports/construction, without signing, fetching trust
roots or contacting Sigstore. Live T2 signing/verification requires network
access and OIDC/trust infrastructure; it is a separate integration lane, never
a prerequisite for the offline smoke. See [CI](.github/workflows/tests.yml).

There is no configured Python typecheck or standalone JS build. To check Python
distribution packaging separately, install `build` in the environment and run
`python -m build` (writes `dist/`); this does not publish anything. For browser
verifier or receipts UI changes, also review valid/tampered synthetic T1 receipts
and the displayed trust limitations in a browser. Python/Node fixture tests
do not establish live Sigstore behavior or browser rendering.

## Status

Phases 0-2 complete (format, producer/sealer, verifier CLI); Phase 3 in progress
(client-side verifier + T2 keyless CI). Part of the Verification Chain program
(HarnessBench + Verification Ledger + CheckSeal on one schema). MIT.
