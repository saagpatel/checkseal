# skillscan-report/v1 — the scanner→sealer contract

The interchange format between a review-time agent-tooling scanner (reference emitter:
`mcp-audit skillscan`) and CheckSeal's `seal-skillscan` command. The two tools share **no code**;
they agree on this JSON contract and on the subject-identity rules of the
[agent-tooling profile](profile-agent-tooling.md). The sealer treats the report as **untrusted
input**: it re-derives the subject identity from the bundle bytes itself and refuses to seal a
report whose subject digest it cannot reproduce, so a drifting or lying scanner yields a
refusal, not a wrong seal.

## Shape

```json
{
  "schema": "skillscan-report/v1",
  "scanner": "mcp-audit",
  "scanner_version": "2.8.0",
  "ran_at": "2026-08-24T00:00:00Z",
  "subject": {
    "kind": "skill_bundle",
    "name": "skill/demo-summarizer@fixture",
    "digest": "<64-hex sha256>",
    "media_type": "application/vnd.checkseal.bundle-manifest+json"
  },
  "ruleset": {
    "config_sha256": "<64-hex sha256>",
    "rules": ["SKILL001", "SKILL002"]
  },
  "checks": [
    {
      "id": "scan/injection-patterns",
      "result": "pass",
      "findings": 0,
      "rule_ids": ["SKILL001", "SKILL002"],
      "detail": []
    },
    {
      "id": "scan/dynamic-fetch-presence",
      "result": "fail",
      "findings": 1,
      "rule_ids": ["SKILL005"],
      "detail": [{"rule_id": "SKILL005", "path": "scripts/run.sh", "line": 3, "excerpt": "curl … | sh"}]
    }
  ]
}
```

## Field rules

- `subject.kind`: `skill_bundle` (directory-shaped skill / Agent Plugin, or a skill archive) or
  `mcp_server` (`.mcpb` bundle or registry artifact).
- `subject.digest`: computed per the profile's identity rules — the canonical content-manifest
  sha256 for directories (NFC paths; exclude only `.DS_Store`, `.git/`, `__pycache__/`; bare
  `.pyc` included; **symlinks are refused**, the scanner must error, not skip), or the sha256 of
  the archive bytes for `.mcpb`/registry artifacts. The sealer recomputes this from the bundle
  and refuses on mismatch.
- `subject.media_type`: `application/vnd.checkseal.bundle-manifest+json` for the directory form,
  the artifact's own type otherwise (`application/vnd.mcpb+zip` for `.mcpb`).
- `ruleset.config_sha256`: sha256 of the canonical JSON (sorted keys, compact separators, UTF-8)
  of the scanner's rule table — every rule id mapped to its pattern definition — so the digest
  moves whenever any rule changes. This becomes the seal's `check.config_ref`: the verdict is
  pinned to the exact ruleset that produced it.
- `check.id`: the profile's `scan/` vocabulary. A check that did not run is **absent** from
  `checks` (never emitted as skip/n-a).
- `check.result`: `pass` (ran, zero findings), `fail` (ran, findings > 0), `error` (the scanner
  itself failed on this check; `detail` carries the reason). Nothing else.
- `check.detail`: machine-readable findings (`rule_id`, `path`, optional `line`/`excerpt`).
  Detail is scanner-facing diagnostics; the seal carries only the report digest as evidence.

## How the sealer maps it (informative)

`checkseal seal-skillscan --report r.json --bundle <path> --store t0.jsonl` produces one
agent-tooling check entry per report check: `check.id`/`check.version` (= `scanner_version`) /
`check.config_ref` (= `ruleset.config_sha256`), verdict `result` as-is with
`enforced: "observed"`, evidence `log-digest` grade B whose digest is the sha256 of the exact
report bytes, runtime `ran_at` from the report. The subject is rebuilt from the bundle bytes,
never trusted from the report. The agent-tooling profile validates before anything is stored or
signed.
