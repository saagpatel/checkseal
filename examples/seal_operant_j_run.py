"""Seal an OPERANT-J judge sitting: sign its VCR receipt as an observed CheckSeal.

The subject is the OPERANT-J VCR receipt file (``vcr-<run_id>.jsonl``, produced by
``operantj/emit_vcr.py``); every case in it becomes one observed ``review`` check. The
seal makes a judge sitting tamper-evident and attributable without re-running it --
honestly observed, claiming no enforcement. The adapter refuses a receipt that claims
any enforcement, so a judge run cannot masquerade as a gate.

    # T1 local demo (self-signed, offline-verifiable):
    python examples/seal_operant_j_run.py --receipt vcr-<run>.jsonl \
        --key t1-key.pem --store /tmp/oj.jsonl --out operant-j.intoto.jsonl

    # store-only, so CI can seal it keyless into a public T2 bundle:
    python examples/seal_operant_j_run.py --receipt vcr-<run>.jsonl --store /tmp/oj.jsonl
"""

from __future__ import annotations

import argparse
import os

from checkseal.operantj import ingest_operant_j_receipt
from checkseal.seal import assemble, sign_local
from checkseal.sign.local import load_private_signer
from checkseal.store import CheckResult, JsonlSealStore


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipt", required=True, help="OPERANT-J VCR receipt (vcr-<run>.jsonl)")
    ap.add_argument("--name", help="override the seal subject name (default: judge id from receipt)")
    ap.add_argument("--store", required=True, help="the T0 store to populate with the observed checks")
    # Signing is optional, exactly as in seal_harness_config.py: with --key/--out this
    # T1-signs the offline demo; omit both to only populate the store, so CI can seal it
    # keyless into a public T2 bundle. The store round-trips the full observed checks.
    ap.add_argument("--key", help="T1 private key; omit for store-only (CI T2) mode")
    ap.add_argument("--out", help="T1 seal output; omit for store-only (CI T2) mode")
    args = ap.parse_args()
    if bool(args.key) != bool(args.out):
        raise SystemExit(
            "--key and --out must be given together (T1 demo) or both omitted (store-only for CI T2)"
        )
    if os.path.exists(args.store):
        raise SystemExit(
            f"--store {args.store} already exists; use a fresh path. The store is append-only, "
            "so reusing it would double the sealed checks."
        )

    subject, entries = ingest_operant_j_receipt(args.receipt, name=args.name)
    store = JsonlSealStore(args.store)
    for entry in entries:
        store.append(CheckResult(subject, entry))

    if args.key:
        predicate = assemble(store, subject)
        signer = load_private_signer(args.key)
        seal = sign_local(predicate, signer, public=False)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(seal.to_intoto_jsonl() + "\n")
        print(f"sealed {len(entries)} observed judge checks for {subject.name} (T1) -> {args.out}")
    else:
        print(f"populated store with {len(entries)} observed judge checks for {subject.name} -> {args.store}")
        print(f"  next: checkseal seal-keyless --store {args.store} --subject {args.receipt} \\")
        print(f"        --name '{subject.name}' --kind artifact --out operant-j.sigstore.json")
    print(f"  subject (receipt) sha256 : {subject.digest}")
    print("  checks all enforced=observed, no enforced_proof (a benchmark observes; it enforces nothing)")


if __name__ == "__main__":
    main()
