// Cross-language proof: a seal SIGNED by the Python implementation is VERIFIED
// by this JavaScript verifier. Run with: node --test js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";

import { renderReport, verifySeal } from "./checkseal_verify.mjs";

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

test("shared valid and invalid schema fixtures are loaded consistently", async () => {
  for (const [name, invalid] of [["valid-statement.json", false], ["invalid-statement.json", true]]) {
    const statement = readFileSync(join(repoRoot, "tests/fixtures/schema", name), "utf8");
    const envelope = { payloadType: "application/vnd.in-toto+json", payload: Buffer.from(statement).toString("base64"), signatures: [] };
    const report = await verifySeal({ envelope, artifactBytes: new Uint8Array() });
    assert.equal(Boolean(report.malformed), invalid, name);
  }
});

test("injection-shaped strings stay inert report text", async () => {
  const statement = JSON.parse(readFileSync(join(repoRoot, "tests/fixtures/schema/valid-statement.json"), "utf8"));
  statement.predicate.checks[0].check.id = '<img src=x onerror="alert(1)">';
  const envelope = { payloadType: "application/vnd.in-toto+json", payload: Buffer.from(JSON.stringify(statement)).toString("base64"), signatures: [] };
  const report = await verifySeal({ envelope, artifactBytes: new Uint8Array() });
  assert.equal(report.entries[0].checkId, '<img src=x onerror="alert(1)">');
  assert.match(renderReport(report), /<img src=x onerror=/);
});

test("malformed entries and tampered payloads produce failed reports", async () => {
  const statement = JSON.parse(readFileSync(join(repoRoot, "tests/fixtures/schema/valid-statement.json"), "utf8"));
  statement.predicate.checks = [null];
  const envelope = { payloadType: "application/vnd.in-toto+json", payload: Buffer.from(JSON.stringify(statement)).toString("base64"), signatures: [] };
  const malformed = await verifySeal({ envelope, artifactBytes: new Uint8Array() });
  assert.equal(malformed.malformed, true);
  const tampered = await verifySeal({ envelope: { ...envelope, payload: "%%%" }, artifactBytes: new Uint8Array() });
  assert.equal(tampered.malformed, true);
  assert.equal(tampered.authenticSubset, false);

  const validStatement = JSON.parse(
    readFileSync(join(repoRoot, "tests/fixtures/schema/valid-statement.json"), "utf8"),
  );
  for (const mutate of [
    (value) => { value._type = "wrong"; },
    (value) => { value.predicateType = "wrong"; },
    (value) => { value.predicate.checks = []; },
    (value) => { value.predicate.checks[0].runtime.duration_ms = -1; },
  ]) {
    const candidate = structuredClone(validStatement);
    mutate(candidate);
    const malformedEnvelope = {
      payloadType: "application/vnd.in-toto+json",
      payload: Buffer.from(JSON.stringify(candidate)).toString("base64"),
      signatures: [],
    };
    const failed = await verifySeal({ envelope: malformedEnvelope, artifactBytes: new Uint8Array() });
    assert.equal(failed.malformed, true);
    assert.equal(failed.authenticSubset, false);
  }
});
