# CheckSeal

CheckSeal creates and verifies signed check receipts for artifacts. A receipt
records which checks ran, their results, and how strongly each result binds. It
uses in-toto Statement v1, DSSE, and Sigstore keyless signing for public seals.

Its trust floor is the weaker of a check's enforcement binding and its evidence
grade. Evidence digests are producer assertions: signing authenticates the
assertion, and verification does not resolve or recompute the evidence bytes.
The verifier recomputes the live subject digest.

## Install

```bash
pip install checkseal
pip install 'checkseal[sign]'      # local Ed25519 signing
pip install 'checkseal[keyless]'   # Sigstore keyless signing
```

## Quickstart (local T1)

```bash
checkseal keygen --out key.pem --pub pub.pem
checkseal seal --store checks.jsonl --subject ./artifact --name artifact/name \
  --key key.pem --out artifact.intoto.jsonl
checkseal verify artifact.intoto.jsonl --subject ./artifact --pubkey pub.pem
```

Public seals must use T2 Sigstore keyless signing from an environment with an
OIDC credential. The manual workflow is
[`.github/workflows/seal.yml`](.github/workflows/seal.yml).

## Verification

The CLI checks the live subject digest, signature, requested freshness, Grade A
re-execution, and HarnessBench proof resolution when an explicit proof root or
resolver is supplied. Proof and re-execution work runs only after authentication
and subject binding succeed. The browser verifier at
[`examples/receipts.html`](examples/receipts.html) checks a smaller subset: the
subject digest, Statement/predicate coupling, Ed25519 signature, and trust floor.
It does not verify Rekor inclusion, re-execution, or HarnessBench proofs.

## Profiles

The N1 profile applies to every seal. The agent-tooling profile constrains
receipts for skills and MCP servers; see
[`docs/profile-agent-tooling.md`](docs/profile-agent-tooling.md). The
[Article 12 mapping](docs/article-12-mapping.md) is a schema note, not legal
advice.

## Development verification

Use the versions pinned by `.python-version` and `.node-version`. Run
`make check` from the repository root for dependency sync, lint, format, strict
typing, Python and Node tests, and a wheel install smoke check. The keyless API
tests do not contact Sigstore; live T2 behavior requires OIDC and trust
infrastructure.

## Status

### Stack

Python 3.12+, Node.js 26.11.1, uv, Ruff, mypy, pytest, Node's built-in test
runner, and wheel packaging.

### Known risks

- Evidence digests are producer assertions; verification does not recompute them.
- JSONL store writes do not lock or recover a corrupt tail.
- Browser checks do not establish Rekor inclusion or live Sigstore behavior.
- Hosted receipt delivery and runtime receipts are outside this repository's
  current verification contract.

### Next steps

- Run `make check` after changes.
- Scope any hosted delivery or live T2 work separately.
