"""Exhaustive single-byte flip enumeration over whole .intoto.jsonl seal files.

Not collected by pytest (it takes minutes). Run it from the repository root:

    uv run python tests/flip_enumeration.py

Three canonical seals are built whose payload lengths are 0, 1 and 2 mod 3, so
every base64 padding shape is covered. Every byte of each seal file is XORed
with every mask 1..255 and verified by the Python CLI verifier, and (when node
is installed) by the JavaScript verifier on the same first line. The script
fails if any accepted flip authenticates different signed bytes (INV-T9) and
prints a per-region count of accepted flips plus every Python/JS disagreement.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _invariant_support import SIGNER, JsWorker, node_binary, raw_public_b64, verify_line  # noqa: E402
from checkseal.dsse import Envelope, pae  # noqa: E402
from checkseal.json_utils import loads_unique_json  # noqa: E402
from checkseal.model import Enforced, EvidenceKind, Grade, Predicate  # noqa: E402
from checkseal.seal import sign_local  # noqa: E402
from conftest import make_entry, make_subject  # noqa: E402

ARTIFACT = b"the essay body"


def _seal(name_suffix: str) -> tuple[bytes, bytes, int]:
    entry = make_entry(enforced=Enforced.ADVISORY, grade=Grade.B, evidence_kind=EvidenceKind.LOG_DIGEST)
    predicate = Predicate(subject=make_subject(ARTIFACT, name="essay/stranded" + name_suffix), checks=[entry])
    seal = sign_local(predicate, SIGNER)
    assert seal.envelope is not None
    return (seal.to_intoto_jsonl() + "\n").encode(), seal.envelope.signing_bytes(), len(seal.envelope.payload)


def _region(text: str, i: int) -> str:
    if text.find('"payload":"') < i < text.find('","payloadType'):
        return "payload base64"
    if text.find('"sig":"') < i < text.rfind('"}]'):
        return "sig base64"
    if text.find('"keyid"') <= i < text.find('"keyid"') + len('"keyid"'):
        return "keyid member name"
    if i == len(text) - 1:
        return "trailing newline"
    return f"other byte {i}"


def main() -> int:
    node = node_binary()
    js = JsWorker(node) if node else None
    pub = raw_public_b64(SIGNER)
    total_flips = 0
    broken = 0
    for suffix in ("", "x", "xy"):
        line, signed, plen = _seal(suffix)
        text = line.decode()
        accepted: collections.Counter[str] = collections.Counter()
        disagreements: collections.Counter[str] = collections.Counter()
        js_checked = 0
        for i in range(len(line)):
            for mask in range(1, 256):
                b = bytearray(line)
                b[i] ^= mask
                mutated = bytes(b)
                total_flips += 1
                out = verify_line(mutated, artifact=ARTIFACT)
                if out.accepted:
                    accepted[_region(text, i)] += 1
                    env = Envelope.from_jsonable(loads_unique_json(mutated.decode().splitlines()[0].strip()))
                    if pae(env.payload_type, env.payload) != signed:
                        broken += 1
                        print(f"INV-T9 BROKEN at byte {i} mask {mask}")
                if js is None:
                    continue
                try:
                    first = mutated.decode("utf-8").split("\n")[0]
                except UnicodeDecodeError:
                    continue  # JS receives parsed objects; invalid UTF-8 never reaches it
                js_checked += 1
                reply = js.verify(first, ARTIFACT, pub)
                js_ok = bool(reply.get("report", {}).get("authenticSubset"))
                if "threw" in reply:
                    disagreements["JS threw"] += 1
                if js_ok != out.accepted:
                    side = "Python only" if out.accepted else "JS only"
                    disagreements[f"{side}: {_region(text, i)} ({mask=:#04x})"] += 1
        print(
            json.dumps(
                {
                    "payload_len_mod_3": plen % 3,
                    "file_bytes": len(line),
                    "flips": len(line) * 255,
                    "python_accepted_by_region": dict(accepted),
                    "js_checked": js_checked,
                    "python_js_disagreements": dict(disagreements),
                },
                sort_keys=True,
            )
        )
    if js is not None:
        js.close()
    print(f"total flips {total_flips}; accepted flips with different signed bytes: {broken}")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
