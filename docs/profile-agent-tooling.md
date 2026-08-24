# Agent-Tooling Profile v0.1 (N3)

**Designation N3, confirmed by the operator 2026-08-24.** Third numbered instrument profile of
the Verification Chain program, alongside N1 (CheckSeal seals) and N2 (HarnessBench dataset
rows).

**Consumes** the VCR v0.2 predicate exactly as CheckSeal produces it (`src/checkseal/model.py`).
This profile constrains which **values** an agent-tooling seal may carry; it changes **no core
field** — no name, no type, no enum value. An agent-tooling seal is an N1 sealed assertion and
must additionally satisfy the N1 profile (`src/checkseal/profile.py`); the validator here
(`src/checkseal/profile_agent_tooling.py`) composes both, producer-side, before signing.

## What this profile is for

A skill or MCP server cannot be certified *safe* — absence of malice is unprovable, a standing
VCR boundary. What can be attested: **these checks ran against these exact bytes, at this time,
with this verdict, and here is the signed evidence.** The receipt model turns the known evasion
channel (artifacts that fetch and execute content at runtime, so the reviewed artifact is not the
artifact that runs) into the strongest argument for byte-pinned evidence.

Positioning against adjacent mechanisms: `mcpb sign` and registry signatures prove **who
published** an artifact; this profile's receipts attest **which checks ran against these exact
bytes**. Identity signing and check receipts are complementary layers, not competitors.

## Subject identity (the registry-poisoning defense)

Registries accept planted entries; names are therefore untrusted. **Identity is bytes.**

| Form | Subject artifact | `digest.sha256` | `mediaType` |
|---|---|---|---|
| Skill directory (`SKILL.md` convention) | canonical content manifest | sha256(manifest bytes) | `application/vnd.checkseal.bundle-manifest+json` |
| Agent Plugin directory (`plugin.json`, Agent Plugins 1.0) | canonical content manifest | sha256(manifest bytes) | `application/vnd.checkseal.bundle-manifest+json` |
| MCP Bundle (`.mcpb` zip) | the zip bytes as distributed | sha256(zip bytes) | `application/vnd.mcpb+zip` |
| Registry package (npm / PyPI artifact) | the published artifact bytes | sha256(artifact bytes) | the artifact's own media type |

Rules:

- `subject.kind` is `"skill_bundle"` for directory- or archive-shaped skills and plugins, and
  `"mcp_server"` for MCP server distributions — first-class kinds added to the core schema by an
  additive delta **signed off 2026-08-24** (same predicateType; every prior record stays valid).
  `"artifact"` remains accepted for records minted before the delta.
- `subject.mediaType` is **mandatory**: it tells a verifier how to recompute identity. The
  manifest media type means "recompute the canonical manifest from the installed tree and hash
  it"; any other media type means "hash the named artifact's raw bytes."
- `subject.name` (`skill/<slug>@<ref>`, `mcp-server/<name>@<version>`) is inert display metadata,
  **never identity**. A subject without a digest is structurally invalid in the base model.

### Canonical content manifest

For directory-shaped bundles, the subject artifact is a JSON object mapping each posix relative
path to the sha256 of that file's bytes, serialized with the library's canonical encoding
(sorted keys, compact separators, UTF-8, no ASCII escaping) — `checkseal.bundle.canonical_manifest`.

Excluded from identity: filesystem noise only — `.DS_Store` and anything under `.git/` or
`__pycache__/` (derived from sources the manifest already covers). **Nothing human-readable or
executable is excluded**: a bare `.pyc` is importable behavior, so it is identity. This
deliberately differs from HarnessBench's harness-config manifest (which excludes READMEs,
because docs do not change a guard's behavior): every file in a skill bundle is model-readable
behavior — a README is prompt-injectable content — so **docs are identity**.

Fail-closed rules: an empty directory has no identity and is refused. **Symlinks are refused** —
a symlinked directory hides reachable content from the manifest, and a link out of the tree
makes the digest depend on out-of-tree state; a bundle that needs a link must ship real files.
Manifest paths are **NFC-normalized**, so the digest does not depend on the producer's
filesystem normalization (APFS vs HFS+/archive round-trips); two files whose paths normalize to
the same key are refused as an ambiguous identity.

The manifest JSON is itself the publishable evidence artifact: per-file inspectable, and
recomputable by any verifier (or a browser) from the installed tree.

## Check vocabulary

Review-time scan checks: `check.kind = "review"`, ids in the `scan/` namespace, chosen to map
onto scanner detector families (MCPAudit is the reference emitter, arriving in Phase 2):

| `check.id` | Attests presence/absence-of-findings for |
|---|---|
| `scan/injection-patterns` | prompt-injection patterns in model-readable text |
| `scan/obfuscated-egress` | obfuscated network egress in code or config |
| `scan/dynamic-fetch-presence` | runtime fetch-and-execute constructs |
| `scan/permission-surface` | declared/derived permission and capability surface |
| `scan/provenance-integrity` | artifact-vs-registry integrity (published hash match) |

- `check.version` = the scanner version that ran.
- `check.config_ref` = sha256 of the scan-configuration manifest, **mandatory** — it pins which
  ruleset produced the verdict. A verdict from an unpinned ruleset is not reproducible.
- The **`runtime/` namespace is reserved** for runtime-behavior receipts (sandboxed observation
  with fetched payloads pinned by digest). Profile v0.1 **rejects** any `runtime/` check so
  half-specified runtime claims cannot ship; the namespace unlocks when the runtime receipt is
  specified (profile v0.2, program Phase 3).
- Any id outside `scan/` is rejected in v0.1. Human editorial review of a skill is a fine thing
  to seal — as a plain N1 seal, outside this profile.

## Verdict rules

- `verdict.enforced` ∈ {`observed`, `advisory`}; **`enforced` is forbidden.** No HarnessBench
  corpus covers scan-gate threat classes, so an `enforced_proof` could never resolve
  (the resolver renders "gate unproven (corpus mismatch)"); the profile refuses the over-claim at
  the producer instead of letting a verifier discover it. If a future HarnessBench corpus
  measures sandboxed skill-execution configs, that is the upgrade path, and it arrives as a
  profile revision, not a producer's decision.
- Scan verdicts SHOULD be `observed` (the scan observed properties of the bytes); `advisory` is
  for checks whose verdict a human review chain acts on. Nothing defaults this for you — the
  emitter states it.
- `verdict.result` ∈ {`pass`, `fail`, `error`} — a whitelist. **`skip` and `n/a` are forbidden**:
  a check that was not attempted must be **absent**, and absence is not claimable (see boundary
  below). `over_blocked` is ground-truth-relative and belongs to the N2 profile only. A scanner
  failure is `result: "error"`, and an error can never render as clean: the verifier counts
  `error` against `checks_passed`.

## Evidence rules

- `evidence.digest` mandatory; inline evidence forbidden (base-model rule, restated).
- `evidence.grade` ∈ {A, B}: **A** when the scan is deterministically re-executable (pinned
  scanner version + `config_ref` + subject digest), **B** when the evidence is an immutable scan
  report identified by digest. A `log-digest` evidence kind may carry grade A when the scan
  meets that re-executability bar; when in doubt, emit B — the honest default for a report you
  cannot promise to reproduce. **Grade C (human attestation) is forbidden** for `scan/` checks —
  a human cannot attest a scanner's verdict.

## Honesty boundaries (inherited, applied)

- A receipt asserts **presence with evidence, never absence**. The verifier never says "safe";
  it says which checks ran, their verdicts, and the trust floor.
- Consumers display `trust_floor = min(binding_rank, grade_rank)`, never a bare enforcement
  word. An `observed` scan check floors at "telemetry only" — deliberately modest.
- **Freshness is first-class.** Public seals are T2 (Sigstore keyless); a requested freshness
  bound that cannot be evaluated fails closed. A skill that updates has new bytes, a new digest,
  and therefore **no inherited receipt**. That is the feature: it is what makes a registry-level
  "verified" badge — which survives the artifact changing underneath it — dishonest by
  comparison.
- **v0.1 boundary, stated:** this profile cannot express "every required check was present"
  (missing-check detection is the Check-Set Manifest, deferred to VCR v2 with an extension point
  reserved). A consumer that needs a required-check policy must impose it consumer-side.

## Worked example: skill-directory subject

The committed fixture `tests/fixtures/agent-tooling/skill-demo/` has this canonical manifest:

```json
{"SKILL.md":"7cddfb3d1b6dd44ec694e9804a63a1af7ea45decd9b2eb06716aca57a948f817","scripts/summarize.py":"78e5a4b956596ec23648f3283c28b49021ec99a3b5f3be56b5e4f3b88011d666"}
```

whose sha256 — the subject digest — is:

```
c3b66f7c14f62ec11e66b301c931726554c7bfc2ab6311cc6e5b76d680818469
```

(`test_spec_example_digest_is_reproducible` keeps this value in lock-step with the fixture.)
A well-formed record over it:

```json
{
  "vcr_version": "0.2",
  "subject": {
    "kind": "skill_bundle",
    "digest": {"sha256": "c3b66f7c14f62ec11e66b301c931726554c7bfc2ab6311cc6e5b76d680818469"},
    "name": "skill/demo-summarizer@fixture",
    "mediaType": "application/vnd.checkseal.bundle-manifest+json"
  },
  "checks": [{
    "check": {
      "id": "scan/injection-patterns",
      "kind": "review",
      "version": "1",
      "config_ref": {"sha256": "<sha256 of the scan-configuration manifest>"}
    },
    "verdict": {"result": "pass", "enforced": "observed"},
    "evidence": {"kind": "log-digest", "grade": "B", "digest": {"sha256": "<sha256 of the scan report>"}},
    "runtime": {"ran_at": "2026-08-24T00:00:00Z", "runner": "ci"},
    "provenance": {"authority": "operator", "instruction_boundary": {"kind": "stored_data_not_instructions"}}
  }]
}
```

## Worked example: `.mcpb` subject

For an archive-shaped distribution the subject is the bytes as distributed — no manifest step:

```json
{
  "kind": "mcp_server",
  "digest": {"sha256": "<sha256 of the .mcpb zip bytes>"},
  "name": "mcp-server/demo-server@1.0.0",
  "mediaType": "application/vnd.mcpb+zip"
}
```

`test_mcpb_archive_subject_verifies` builds and verifies exactly this shape.

## Conformance

The profile's conformance cases are `tests/test_profile_agent_tooling.py`: well-formed seals
verify; a forged subject digest fails `authentic`; drifted bytes break the receipt; a missing
live subject fails closed; `enforced`, `skip`/`n/a`/`over_blocked`, grade C, missing
`config_ref`, and the `runtime/` namespace are unmintable (including when spelled as plain
strings rather than enums); a scanner `error` seals honestly and never renders clean; a stale T2
seal fails closed; the canonical manifest is deterministic, refuses symlinks, normalizes
unicode paths, and excludes noise only.

Scope, stated: the agent-tooling rules run **producer-side** in v0.1 — "unmintable" means
through this library. The verifier applies the base-model and N1 re-checks (E1, enforced-proof
resolution, grade-C authority) but not the agent-tooling rules; a verifier-side profile check on
seals minted elsewhere is a v0.2 candidate alongside the `runtime/` namespace.
