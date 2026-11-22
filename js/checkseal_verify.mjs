// CheckSeal client-side verifier: the honest subset that runs in a browser.
//
// This is the /receipts verifier. It does the steps a browser CAN do soundly and
// says loudly which it cannot. It deliberately does NOT claim to be the full
// Verifier Contract: re-execution (step 3), enforced_proof resolution against
// HarnessBench (step 4), and full Rekor inclusion-proof checking are CLI-only.
//
// What it DOES check:
//   1. recompute the live subject digest (SubtleCrypto) and compare to the seal.
//   2. the DSSE payload's Statement subject matches the predicate subject
//      (no showing one subject in the envelope and another in the claim).
//   3. the Ed25519 signature over the DSSE PAE (T1 seals, or a T2 bundle whose
//      signing key is supplied out of band), honouring the keyid hint exactly as
//      the Python verifier does.
//   5. render trust_floor per check, never a bare "enforced".
//
// Honest subset: it parses envelopes and Statements with the same rules as the
// Python CLI (canonical padded base64, strict JSON, the vendored VCR v0.2 schema),
// so a browser PASS never accompanies a CLI refusal of those same steps.
//
// Works in a browser and in Node (both expose crypto.subtle, atob, btoa, TextEncoder).

const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const PREDICATE_TYPE = "https://saagarpatel.dev/vcr/v0.2";
const VCR_VERSION = "0.2";
export const MAX_JSON_DEPTH = 64;

// Maps, not object literals: "constructor", "__proto__" and friends must not
// resolve to inherited members.
const BINDING_RANK = new Map([["enforced", 2], ["advisory", 1], ["observed", 0]]);
const GRADE_RANK = new Map([["A", 2], ["B", 1], ["C", 0]]);
const FLOOR_LABEL = new Map([[2, "enforced + reproducible"], [1, "surfaced"], [0, "telemetry only"]]);

const CHECK_KINDS = ["review", "guard", "human"];
const RESULTS = ["pass", "fail", "over_blocked", "error", "skip", "n/a"];
const ENFORCED = ["enforced", "advisory", "observed"];
const EVIDENCE_KINDS = ["exit-code", "diff-digest", "log-digest", "transcript-digest", "reviewer-id"];
const GRADES = ["A", "B", "C"];
const RUNNERS = ["fleet", "ci", "human"];
const AUTHORITIES = ["operator", "agent", "ingested"];

const NOT_CHECKED = [
  "step 3 re-execution of enforced Grade-A checks",
  "step 4 enforced_proof resolution against HarnessBench",
  "step 2 full Rekor inclusion-proof (only the signature is checked here)",
];

const subtle = (globalThis.crypto || {}).subtle;

// No regex with a repeated group runs over untrusted input: V8's backtracking
// stack overflows on long strings (about 20 MB of base64, or a check.id with a
// few million segments), where Python's re engine does not. Linear loops instead.
const SHA256_HEX = /^[0-9a-f]{64}$/; // fixed width, no repetition of a group

function isB64Char(c) {
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 43 || c === 47;
}

function isCanonicalB64Shape(s) {
  if (s.length % 4 !== 0) return false;
  let pad = 0;
  while (pad < s.length && s[s.length - 1 - pad] === "=") pad += 1;
  if (pad > 2) return false;
  for (let i = 0; i < s.length - pad; i++) if (!isB64Char(s.charCodeAt(i))) return false;
  return true;
}

function isLowerAlnum(c) { return (c >= "a" && c <= "z") || (c >= "0" && c <= "9"); }

// ^[a-z0-9]+(/[a-z0-9-]+)*$ without a regex.
function isCheckId(s) {
  let start = 0;
  let first = true;
  for (let i = 0; i <= s.length; i++) {
    if (i === s.length || s[i] === "/") {
      if (i === start) return false;
      start = i + 1;
      first = false;
    } else if (!(isLowerAlnum(s[i]) || (!first && s[i] === "-"))) {
      return false;
    }
  }
  return true;
}

// Code points, as Python's len() counts them, without materializing an array.
function codePointLength(s) {
  let n = 0;
  for (const _ of s) n += 1;
  return n;
}

function ensure(cond, message) {
  if (!cond) throw new Error(message);
}

function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }

// Own-property read: untrusted JSON never reaches Object.prototype members.
function own(value, key) {
  return object(value) && Object.hasOwn(value, key) ? value[key] : undefined;
}

// Canonical padded standard base64 only (same rule as checkseal.dsse.b64decode_canonical):
// no whitespace, no URL-safe alphabet, mandatory padding, zero trailing bits.
function b64ToBytes(b64) {
  ensure(typeof b64 === "string" && isCanonicalB64Shape(b64), "not canonical padded base64");
  const bin = atob(b64);
  ensure(btoa(bin) === b64, "non-canonical base64 (non-zero trailing bits)");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function pae(payloadType, payload) {
  const enc = new TextEncoder();
  const head = enc.encode(`DSSEv1 ${enc.encode(payloadType).length} ${payloadType} ${payload.length} `);
  const out = new Uint8Array(head.length + payload.length);
  out.set(head, 0);
  out.set(payload, head.length);
  return out;
}

async function sha256Hex(bytes) {
  const digest = await subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function trustFloor(entry) {
  const enforced = own(own(entry, "verdict"), "enforced");
  const grade = own(own(entry, "evidence"), "grade");
  const b = typeof enforced === "string" && BINDING_RANK.has(enforced) ? BINDING_RANK.get(enforced) : 0;
  const g = typeof grade === "string" && GRADE_RANK.has(grade) ? GRADE_RANK.get(grade) : 0;
  const f = Math.min(b, g);
  return { floor: f, label: FLOOR_LABEL.get(f) };
}

// One string-aware pass: duplicate member names (compared after unescaping) and
// nesting depth of arrays and objects. Mirrors checkseal.json_utils.
function scanJsonText(text) {
  const stack = [];
  for (let i = 0; i < text.length;) {
    if (text[i] === '"') {
      let end = i + 1;
      while (end < text.length) {
        if (text[end] === "\\") end += 2;
        else if (text[end] === '"') break;
        else end += 1;
      }
      let next = end + 1;
      while (/\s/.test(text[next] || "")) next += 1;
      const current = stack[stack.length - 1];
      if (text[next] === ":" && current instanceof Set) {
        const key = JSON.parse(text.slice(i, end + 1));
        if (current.has(key)) throw new Error("duplicate JSON object member");
        current.add(key);
      }
      i = end + 1;
    } else {
      if (text[i] === "{" || text[i] === "[") {
        stack.push(text[i] === "{" ? new Set() : null);
        if (stack.length > MAX_JSON_DEPTH) throw new Error(`JSON nesting deeper than ${MAX_JSON_DEPTH}`);
      } else if (text[i] === "}" || text[i] === "]") {
        stack.pop();
      }
      i += 1;
    }
  }
}

// JSON.parse reads out-of-range literals (1e400, a 400-digit integer) as
// +/-Infinity; the Python side refuses them, so refuse them here too.
function rejectNonFinite(value) {
  const pending = [value];
  while (pending.length) {
    const v = pending.pop();
    if (typeof v === "number" && !Number.isFinite(v)) throw new Error("JSON number is not a finite double");
    // One push per element: spreading a wide collection into push() overflows
    // the engine's argument limit (about 120k on V8).
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) pending.push(v[i]);
    } else if (object(v)) {
      for (const key in v) if (Object.hasOwn(v, key)) pending.push(v[key]);
    }
  }
}

// Strict JSON, identical in acceptance to checkseal.json_utils.loads_unique_json.
export function parseUniqueJson(text) {
  ensure(typeof text === "string", "JSON text must be a string");
  const value = JSON.parse(text);
  scanJsonText(text);
  rejectNonFinite(value);
  return value;
}

// ---- envelope and Statement validation (mirrors checkseal.dsse / model / statement) ----

function str(value, ctx, maxLen) {
  ensure(typeof value === "string", `${ctx}: must be a string`);
  if (maxLen !== undefined) ensure(codePointLength(value) <= maxLen, `${ctx}: exceeds ${maxLen} chars`);
  return value;
}

function oneOf(value, allowed, ctx) {
  ensure(typeof value === "string" && allowed.includes(value), `${ctx}: unexpected value`);
  return value;
}

function members(d, ctx, required, optional = []) {
  ensure(object(d), `${ctx}: must be an object`);
  for (const k of required) ensure(Object.hasOwn(d, k), `${ctx}: missing required member ${k}`);
  for (const k of Object.keys(d)) {
    ensure(required.includes(k) || optional.includes(k), `${ctx}: unknown member ${JSON.stringify(k)}`);
  }
  return d;
}

function sha256Exact(value, ctx) {
  ensure(typeof value === "string" && SHA256_HEX.test(value), `${ctx}: not a lowercase 64-hex sha256`);
  return value;
}

function digestSet(d, ctx) {
  return sha256Exact(members(d, ctx, ["sha256"]).sha256, ctx);
}

function validateSubject(d) {
  ensure(object(d), "subject: must be an object");
  for (const k of ["kind", "digest", "name"]) ensure(Object.hasOwn(d, k), `subject: missing ${k}`);
  if (Object.hasOwn(d, "mediaType")) str(d.mediaType, "subject.mediaType");
  str(d.kind, "subject.kind"); // free text: unknown kinds render conservatively
  digestSet(d.digest, "subject.digest");
  str(d.name, "subject.name", 256);
}

function validateEntry(d, index) {
  const ctx = `checks[${index}]`;
  members(d, ctx, ["check", "verdict", "evidence", "runtime", "provenance"]);

  const check = members(d.check, `${ctx}.check`, ["id", "kind", "version"], ["config_ref"]);
  ensure(isCheckId(str(check.id, `${ctx}.check.id`)), `${ctx}.check.id: bad pattern`);
  oneOf(check.kind, CHECK_KINDS, `${ctx}.check.kind`);
  str(check.version, `${ctx}.check.version`);
  if (Object.hasOwn(check, "config_ref")) digestSet(check.config_ref, `${ctx}.check.config_ref`);

  const verdict = members(d.verdict, `${ctx}.verdict`, ["result", "enforced"], ["enforced_proof"]);
  oneOf(verdict.result, RESULTS, `${ctx}.verdict.result`);
  oneOf(verdict.enforced, ENFORCED, `${ctx}.verdict.enforced`);
  if (Object.hasOwn(verdict, "enforced_proof")) {
    const proof = members(verdict.enforced_proof, `${ctx}.verdict.enforced_proof`, ["sha256", "uri"]);
    sha256Exact(proof.sha256, `${ctx}.verdict.enforced_proof.sha256`);
    str(proof.uri, `${ctx}.verdict.enforced_proof.uri`);
  }

  const evidence = members(d.evidence, `${ctx}.evidence`, ["kind", "grade", "digest"], ["uri"]);
  oneOf(evidence.kind, EVIDENCE_KINDS, `${ctx}.evidence.kind`);
  oneOf(evidence.grade, GRADES, `${ctx}.evidence.grade`);
  digestSet(evidence.digest, `${ctx}.evidence.digest`);
  if (Object.hasOwn(evidence, "uri")) str(evidence.uri, `${ctx}.evidence.uri`);

  const runtime = members(d.runtime, `${ctx}.runtime`, ["ran_at", "runner"], ["duration_ms", "env_digest"]);
  str(runtime.ran_at, `${ctx}.runtime.ran_at`);
  oneOf(runtime.runner, RUNNERS, `${ctx}.runtime.runner`);
  if (Object.hasOwn(runtime, "duration_ms")) {
    const dur = runtime.duration_ms;
    ensure(typeof dur === "number" && Number.isInteger(dur) && dur >= 0, `${ctx}.runtime.duration_ms: non-negative int`);
  }
  if (Object.hasOwn(runtime, "env_digest")) digestSet(runtime.env_digest, `${ctx}.runtime.env_digest`);

  const provenance = members(d.provenance, `${ctx}.provenance`, ["authority", "instruction_boundary"]);
  oneOf(provenance.authority, AUTHORITIES, `${ctx}.provenance.authority`);
  str(members(provenance.instruction_boundary, `${ctx}.provenance.instruction_boundary`, ["kind"]).kind,
    `${ctx}.provenance.instruction_boundary.kind`);
}

function validateStatement(statement) {
  ensure(object(statement), "statement: must be an object");
  ensure(own(statement, "_type") === STATEMENT_TYPE, "unsupported Statement type");
  ensure(own(statement, "predicateType") === PREDICATE_TYPE, "unsupported predicate type");
  const predicate = members(own(statement, "predicate"), "predicate", ["vcr_version", "subject", "checks"]);
  ensure(str(predicate.vcr_version, "vcr_version") === VCR_VERSION, "unsupported VCR predicate version");
  ensure(Array.isArray(predicate.checks) && predicate.checks.length > 0, "predicate checks must be non-empty");
  validateSubject(predicate.subject);
  predicate.checks.forEach(validateEntry);
  const subjects = own(statement, "subject");
  ensure(Array.isArray(subjects) && subjects.length === 1 && object(subjects[0]), "Statement subject must contain one object");
  ensure(object(own(subjects[0], "digest")), "Statement subject digest must be an object");
  return predicate;
}

function parseEnvelope(envelope) {
  ensure(object(envelope), "envelope: must be an object");
  const payloadType = own(envelope, "payloadType");
  ensure(typeof payloadType === "string", "envelope.payloadType: string");
  const payload = b64ToBytes(own(envelope, "payload"));
  const raw = own(envelope, "signatures");
  ensure(Array.isArray(raw) && raw.length > 0, "envelope.signatures: non-empty list");
  const signatures = raw.map((rs, i) => {
    ensure(object(rs), `signatures[${i}]: object`);
    const sig = b64ToBytes(own(rs, "sig"));
    ensure(sig.length > 0, `signatures[${i}].sig: empty`);
    const keyid = own(rs, "keyid");
    const cert = own(rs, "cert");
    ensure(keyid === undefined || keyid === null || typeof keyid === "string", `signatures[${i}].keyid: must be a string`);
    ensure(cert === undefined || cert === null || typeof cert === "string", `signatures[${i}].cert: must be a string`);
    return { sig, keyid: typeof keyid === "string" ? keyid : null };
  });
  ensure(payloadType === PAYLOAD_TYPE, `unexpected DSSE payloadType ${JSON.stringify(payloadType)}`);
  return { payloadType, payload, signatures };
}

function failedReport(subjectReason, signatureReason) {
  return {
    authenticSubset: false,
    malformed: true,
    subjectCoupled: false,
    subjectDigestOk: false,
    subjectReason,
    signatureOk: false,
    signatureReason,
    entries: [],
    notChecked: NOT_CHECKED,
  };
}

// Call parseUniqueJson on the raw DSSE line before passing its parsed object.
// This function cannot detect duplicate keys in an object that is already parsed.
// publicKeyRaw: 32-byte Uint8Array Ed25519 public key (T1: supplied out of band;
// T2: extracted from the bundle's Fulcio cert by the caller). Returns the report.
// Untrusted input never makes it throw: every malformed or tampered envelope or
// payload produces a failed report.
export async function verifySeal({ envelope, artifactBytes, publicKeyRaw }) {
  if (!subtle) throw new Error("WebCrypto SubtleCrypto is unavailable in this environment");
  try {
    return await verifyParsed(envelope, artifactBytes, publicKeyRaw);
  } catch (err) {
    // Defence in depth: the validators above should leave nothing to catch.
    return failedReport("payload is malformed or tampered", `verifier error: ${err && err.message}`);
  }
}

async function verifyParsed(envelope, artifactBytes, publicKeyRaw) {
  // Step 6: the envelope and payload are untrusted.
  let env;
  let statement;
  let predicate;
  try {
    env = parseEnvelope(envelope);
    const payloadText = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(env.payload);
    statement = parseUniqueJson(payloadText);
    predicate = validateStatement(statement);
  } catch (err) {
    return failedReport("payload is malformed or tampered", `payload unparseable: ${err.message}`);
  }

  // step 2 (subject coupling): statement subject must equal predicate subject.
  const s0 = statement.subject[0];
  const sealedDigest = predicate.subject.digest.sha256;
  const subjectCoupled = own(s0, "name") === predicate.subject.name && own(s0.digest, "sha256") === sealedDigest;

  // step 1: recompute the live subject digest.
  let subjectDigestOk = false;
  let subjectReason = "no artifact bytes supplied; cannot bind the seal to served content";
  if (artifactBytes) {
    const live = await sha256Hex(artifactBytes);
    subjectDigestOk = live === sealedDigest;
    subjectReason = subjectDigestOk
      ? `live digest matches (${live.slice(0, 12)}...)`
      : `live digest ${live.slice(0, 12)}... != sealed ${sealedDigest.slice(0, 12)}...`;
  }

  // step 3 of DSSE: signature over PAE, with the keyid hint checked as in Python.
  let signatureOk = false;
  let signatureReason = "no Ed25519 public key supplied";
  if (publicKeyRaw) {
    try {
      const keyid = `ed25519:${(await sha256Hex(publicKeyRaw)).slice(0, 16)}`;
      const key = await subtle.importKey("raw", publicKeyRaw, { name: "Ed25519" }, false, ["verify"]);
      const signed = pae(env.payloadType, env.payload);
      for (const sig of env.signatures) {
        if (sig.keyid !== null && sig.keyid !== keyid) {
          signatureReason = `key id mismatch: envelope ${JSON.stringify(sig.keyid)} != verifier ${JSON.stringify(keyid)}`;
          continue;
        }
        if (await subtle.verify({ name: "Ed25519" }, key, sig.sig, signed)) {
          signatureOk = true;
          signatureReason = "Ed25519 signature valid over DSSE PAE";
          break;
        }
        signatureReason = "Ed25519 signature did not verify under the supplied key";
      }
    } catch (err) {
      // Older browsers lack WebCrypto Ed25519; degrade honestly, never throw.
      signatureReason = `Ed25519 unavailable in this browser (${err.name}); verify with the CLI`;
    }
  }

  // step 5: render trust_floor per check.
  const entries = predicate.checks.map((entry) => {
    const { floor, label } = trustFloor(entry);
    return {
      checkId: entry.check.id,
      result: entry.verdict.result,
      enforced: entry.verdict.enforced,
      trustFloor: floor,
      trustFloorLabel: label,
    };
  });

  const authenticSubset = subjectCoupled && subjectDigestOk && signatureOk;
  return {
    authenticSubset, // the browser-checkable subset only; NOT the full contract
    subjectCoupled,
    subjectDigestOk,
    subjectReason,
    signatureOk,
    signatureReason,
    entries,
    notChecked: NOT_CHECKED,
  };
}

export function renderReport(r) {
  const lines = [
    `subject digest: ${r.subjectDigestOk ? "OK" : "MISMATCH"} - ${r.subjectReason}`,
    `subject coupling: ${r.subjectCoupled ? "OK" : "MISMATCH"}`,
    `signature: ${r.signatureOk ? "OK" : "INVALID"} - ${r.signatureReason}`,
  ];
  for (const e of r.entries) {
    lines.push(`  - ${e.checkId}: result=${e.result} floor=${e.trustFloor} (${e.trustFloorLabel})`);
  }
  lines.push(`browser-checkable subset: ${r.authenticSubset ? "PASS" : "FAIL"}`);
  lines.push(`NOT checked here (run the CLI): ${r.notChecked.join("; ")}`);
  return lines.join("\n");
}
