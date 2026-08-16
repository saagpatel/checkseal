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
//      signing key is supplied out of band).
//   5. render trust_floor per check, never a bare "enforced".
//
// Works in a browser and in Node (both expose crypto.subtle, atob, TextEncoder).

const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const BINDING_RANK = { enforced: 2, advisory: 1, observed: 0 };
const GRADE_RANK = { A: 2, B: 1, C: 0 };
const FLOOR_LABEL = { 2: "enforced + reproducible", 1: "surfaced", 0: "telemetry only" };

const NOT_CHECKED = [
  "step 3 re-execution of enforced Grade-A checks",
  "step 4 enforced_proof resolution against HarnessBench",
  "step 2 full Rekor inclusion-proof (only the signature is checked here)",
];

const subtle = (globalThis.crypto || {}).subtle;

function b64ToBytes(b64) {
  const bin = atob(b64);
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
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function trustFloor(entry) {
  const b = BINDING_RANK[entry.verdict.enforced] ?? 0;
  const g = GRADE_RANK[entry.evidence.grade] ?? 0;
  const f = Math.min(b, g);
  return { floor: f, label: FLOOR_LABEL[f] };
}

// publicKeyRaw: 32-byte Uint8Array Ed25519 public key (T1: supplied out of band;
// T2: extracted from the bundle's Fulcio cert by the caller). Returns the report.
export async function verifySeal({ envelope, artifactBytes, publicKeyRaw }) {
  if (!subtle) throw new Error("WebCrypto SubtleCrypto is unavailable in this environment");

  if (envelope.payloadType !== PAYLOAD_TYPE) {
    throw new Error(`unexpected DSSE payloadType ${envelope.payloadType}`);
  }

  // Step 6: the payload is untrusted. A malformed or tampered payload must
  // produce a failed report, never an exception the caller forgets to catch.
  let payload;
  let statement;
  let predicate;
  try {
    payload = b64ToBytes(envelope.payload);
    statement = JSON.parse(new TextDecoder().decode(payload));
    predicate = statement.predicate;
    if (!predicate || !predicate.subject || !predicate.subject.digest) {
      throw new Error("missing predicate.subject.digest");
    }
  } catch (err) {
    return {
      authenticSubset: false,
      malformed: true,
      subjectCoupled: false,
      subjectDigestOk: false,
      subjectReason: "payload is malformed or tampered",
      signatureOk: false,
      signatureReason: `payload unparseable: ${err.message}`,
      entries: [],
      notChecked: NOT_CHECKED,
    };
  }

  // step 2 (subject coupling): statement subject must equal predicate subject.
  const s0 = (statement.subject || [])[0] || {};
  const subjectCoupled =
    s0.name === predicate.subject.name &&
    (s0.digest || {}).sha256 === predicate.subject.digest.sha256;

  // step 1: recompute the live subject digest.
  let subjectDigestOk = false;
  let subjectReason = "no artifact bytes supplied; cannot bind the seal to served content";
  if (artifactBytes) {
    const live = await sha256Hex(artifactBytes);
    subjectDigestOk = live === predicate.subject.digest.sha256;
    subjectReason = subjectDigestOk
      ? `live digest matches (${live.slice(0, 12)}...)`
      : `live digest ${live.slice(0, 12)}... != sealed ${predicate.subject.digest.sha256.slice(0, 12)}...`;
  }

  // step 3 of DSSE: signature over PAE.
  let signatureOk = false;
  let signatureReason = "no Ed25519 public key supplied";
  if (publicKeyRaw) {
    try {
      const key = await subtle.importKey("raw", publicKeyRaw, { name: "Ed25519" }, false, ["verify"]);
      const signed = pae(envelope.payloadType, payload);
      for (const sig of envelope.signatures || []) {
        const ok = await subtle.verify({ name: "Ed25519" }, key, b64ToBytes(sig.sig), signed);
        if (ok) {
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
  const entries = (predicate.checks || []).map((entry) => {
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
