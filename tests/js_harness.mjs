// Test-only line-protocol driver for js/checkseal_verify.mjs, used by
// tests/test_inv_js_parity.py. One JSON request per stdin line, one JSON reply
// per stdout line. The verifier source is loaded unchanged; a test-only export
// line is appended so its private helpers (pae, trustFloor, b64ToBytes) can be
// compared against the Python implementation directly.
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";

const src = readFileSync(new URL("../js/checkseal_verify.mjs", import.meta.url), "utf8");
const withTestExports = `${src}\nexport { pae as __pae, trustFloor as __trustFloor, b64ToBytes as __b64ToBytes };\n`;
const mod = await import(`data:text/javascript;base64,${Buffer.from(withTestExports).toString("base64")}`);

const bytes = (b64) => Uint8Array.from(Buffer.from(b64, "base64"));
const toB64 = (u8) => Buffer.from(u8).toString("base64");

async function handle(req) {
  switch (req.op) {
    case "verify": {
      let envelope;
      try {
        envelope = mod.parseUniqueJson(req.envelope);
      } catch (err) {
        return { parseError: String(err.message) };
      }
      try {
        const report = await mod.verifySeal({
          envelope,
          artifactBytes: bytes(req.artifact),
          publicKeyRaw: req.pubkey === null ? undefined : bytes(req.pubkey),
        });
        return { report };
      } catch (err) {
        return { threw: `${err.name}: ${err.message}` };
      }
    }
    case "unique": {
      try {
        mod.parseUniqueJson(req.text);
        return { ok: true };
      } catch (err) {
        return { ok: false, error: String(err.message) };
      }
    }
    case "pae":
      return { pae: toB64(mod.__pae(req.type, bytes(req.payload))) };
    case "b64": {
      try {
        return { bytes: toB64(mod.__b64ToBytes(req.text)) };
      } catch (err) {
        return { error: err.name };
      }
    }
    case "floor": {
      const { floor, label } = mod.__trustFloor(req.entry);
      return { floor: String(floor), label: label === undefined ? null : label };
    }
    default:
      return { error: `unknown op ${req.op}` };
  }
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (!line) continue;
  const reply = await handle(JSON.parse(line));
  process.stdout.write(`${JSON.stringify(reply)}\n`);
}
