// Cross-language proof: a seal SIGNED by the Python implementation is VERIFIED
// by this JavaScript verifier. Run with: node --test js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifySeal } from "./checkseal_verify.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function fixture() {
  const out = execFileSync("python3", ["tests/gen_js_fixture.py"], {
    cwd: repoRoot,
    env: { ...process.env, PYTHONPATH: "src" },
  });
  return JSON.parse(out.toString());
}

const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

test("valid Python-signed seal verifies in JS", async () => {
  const f = fixture();
  const r = await verifySeal({
    envelope: f.envelope,
    artifactBytes: b64(f.artifact_b64),
    publicKeyRaw: b64(f.pubkey_raw_b64),
  });
  assert.equal(r.authenticSubset, true, JSON.stringify(r));
  assert.equal(r.signatureOk, true);
  assert.equal(r.subjectDigestOk, true);
  assert.equal(r.subjectCoupled, true);
  assert.equal(r.entries[0].checkId, "review/rights-gate");
  assert.equal(r.entries[0].trustFloor, 1); // advisory + grade B
});

test("tampered artifact is caught (digest mismatch)", async () => {
  const f = fixture();
  const r = await verifySeal({
    envelope: f.envelope,
    artifactBytes: new TextEncoder().encode("a different artifact"),
    publicKeyRaw: b64(f.pubkey_raw_b64),
  });
  assert.equal(r.subjectDigestOk, false);
  assert.equal(r.authenticSubset, false);
});

test("wrong public key fails the signature", async () => {
  const f = fixture();
  const r = await verifySeal({
    envelope: f.envelope,
    artifactBytes: b64(f.artifact_b64),
    publicKeyRaw: b64(f.wrong_pubkey_raw_b64),
  });
  assert.equal(r.signatureOk, false);
  assert.equal(r.authenticSubset, false);
});

test("a mutated payload is rejected (tampered claim)", async () => {
  const f = fixture();
  // Flip a byte inside a string value so the JSON still parses but the signed
  // bytes no longer match: the signature must fail.
  const payload = b64(f.envelope.payload);
  const text = new TextDecoder().decode(payload);
  const idx = text.indexOf("essay/stranded") + 2; // inside the subject name
  payload[idx] ^= 0x01;
  const mutated = { ...f.envelope, payload: Buffer.from(payload).toString("base64") };
  const r = await verifySeal({
    envelope: mutated,
    artifactBytes: b64(f.artifact_b64),
    publicKeyRaw: b64(f.pubkey_raw_b64),
  });
  assert.equal(r.authenticSubset, false);
  assert.equal(r.signatureOk, false);
});

test("a structurally broken payload fails gracefully, no throw", async () => {
  const f = fixture();
  const payload = b64(f.envelope.payload);
  payload[0] ^= 0xff; // corrupts the JSON entirely
  const mutated = { ...f.envelope, payload: Buffer.from(payload).toString("base64") };
  const r = await verifySeal({
    envelope: mutated,
    artifactBytes: b64(f.artifact_b64),
    publicKeyRaw: b64(f.pubkey_raw_b64),
  });
  assert.equal(r.malformed, true);
  assert.equal(r.authenticSubset, false);
});
