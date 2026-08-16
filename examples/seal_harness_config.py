"""Produce the first real ENFORCED CheckSeal: a harness config whose gate is proven.

A worked example on REAL evidence with no fabrication. The subject is a harness
config (HarnessBench's ``semantic-clean-room`` subject); the single check asserts
that its destructive-execution guard is ENFORCED, and it backs that claim with the
actual HarnessBench report that measured it. The claim binds cryptographically:
the report's ``config_sha256`` equals the check's ``config_ref`` equals the
subject digest, so the seal cannot cite a report of some other config. This is the
honesty boundary the whole library exists to hold (CONTRACT-DELTA ask b), now
demonstrable because HarnessBench declares ``config_sha256``.

    python examples/seal_harness_config.py \
        --subject examples/artifacts/harnessbench-semantic-clean-room.config-manifest.json \
        --report examples/artifacts/harnessbench-semantic-clean-room.v1.json \
        --report-uri examples/artifacts/harnessbench-semantic-clean-room.v1.json \
        --key <t1-key.pem> --store /tmp/hc.jsonl \
        --out examples/artifacts/harness-config.intoto.jsonl

The subject artifact is the config's canonical content manifest, whose sha256 IS
the ``config_sha256`` HarnessBench measured; a verifier recomputes it and matches.
The check is Grade B (the immutable HarnessBench report is the evidence) with a
rerunnable ``config_ref``, which is exactly what invariant E1 requires to back an
enforced verdict without re-executing the guard at verify time.
"""

from __future__ import annotations

import argparse
import json

from checkseal.digest import sha256_file
from checkseal.model import (
    Authority,
    Check,
    CheckEntry,
    CheckKind,
    Enforced,
    EnforcedProof,
    Evidence,
    EvidenceKind,
    Grade,
    Provenance,
    Result,
    Runner,
    Runtime,
    Subject,
    SubjectKind,
    Verdict,
)
from checkseal.seal import assemble, sign_local
from checkseal.sign.local import load_private_signer
from checkseal.store import CheckResult, JsonlSealStore

# Mirror the resolver's floor so the example refuses to seal what verify would reject.
EES_FLOOR = 0.5


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject", required=True, help="the config manifest; its sha256 is config_sha256")
    ap.add_argument("--name", default="harnessbench-semantic-clean-room")
    ap.add_argument("--report", required=True, help="the HarnessBench report JSON (evidence)")
    ap.add_argument(
        "--report-uri", required=True, help="the URI to record for enforced_proof (repo-relative)"
    )
    ap.add_argument("--as-of", default="2026-08-16", help="YYYY-MM-DD the measurement is stamped with")
    ap.add_argument("--store", required=True, help="the T0 store to populate with the enforced check")
    # Signing is optional. With --key/--out this T1-signs (the offline demo). Omit
    # both to only populate the store, so CI can seal-keyless it into a public T2
    # bundle (the store round-trips the full enforced check, enforced_proof and all).
    ap.add_argument("--key", help="T1 private key; omit for store-only (CI T2) mode")
    ap.add_argument("--out", help="T1 seal output; omit for store-only (CI T2) mode")
    args = ap.parse_args()
    _refuse_unless(
        bool(args.key) == bool(args.out),
        "--key and --out must be given together (T1 demo) or both omitted (store-only for CI T2)",
    )

    report = json.load(open(args.report, encoding="utf-8"))
    _refuse_unless(
        str(report.get("schema", "")).startswith("harnessbench-report/"), "not a HarnessBench report"
    )
    config_sha = report.get("config_sha256")
    threat_class = report.get("threat_class")
    ees = report.get("ees")
    verdicts = report.get("verdicts", {})
    _refuse_unless(
        isinstance(config_sha, str), "report declares no config_sha256 (needs CONTRACT-DELTA ask b)"
    )
    _refuse_unless(isinstance(threat_class, str) and threat_class, "report declares no threat_class")
    _refuse_unless(
        isinstance(ees, (int, float)) and ees >= EES_FLOOR, f"report EES {ees} below floor {EES_FLOOR}"
    )
    _refuse_unless(
        int(verdicts.get("enforced", 0)) > 0 and int(verdicts.get("advised", 0)) == 0,
        "report config does not enforce (enforced<=0 or advised>0)",
    )

    # The subject must BE the config the report measured, or the enforced claim is
    # about the wrong thing. This is the cryptographic honesty gate.
    subject_digest = sha256_file(args.subject)
    _refuse_unless(
        subject_digest == config_sha,
        f"subject digest {subject_digest[:12]}... != report config_sha256 {str(config_sha)[:12]}...; "
        "the manifest is not the config this report measured",
    )

    report_digest = sha256_file(args.report)
    subject = Subject(kind=SubjectKind.HARNESS_CONFIG.value, digest=subject_digest, name=args.name)

    gate = CheckEntry(
        check=Check(
            id=f"guard/{threat_class}",
            kind=CheckKind.GUARD,
            version=str(report.get("corpus_version", "1")),
            config_ref=config_sha,
        ),
        verdict=Verdict(
            result=Result.PASS,
            enforced=Enforced.ENFORCED,
            enforced_proof=EnforcedProof(sha256=report_digest, uri=args.report_uri),
        ),
        # Grade B: the evidence is the immutable HarnessBench report; config_ref
        # makes it rerunnable, which E1 requires to back an enforced verdict.
        evidence=Evidence(
            kind=EvidenceKind.LOG_DIGEST, grade=Grade.B, digest=report_digest, uri=args.report_uri
        ),
        runtime=Runtime(ran_at=args.as_of + "T00:00:00Z", runner=Runner.CI),
        provenance=Provenance(authority=Authority.AGENT),
    )

    store = JsonlSealStore(args.store)
    store.append(CheckResult(subject, gate))

    if args.key:
        predicate = assemble(store, subject)
        signer = load_private_signer(args.key)
        seal = sign_local(predicate, signer, public=False)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(seal.to_intoto_jsonl() + "\n")
        print(f"sealed 1 enforced check for {subject.name} (T1) -> {args.out}")
    else:
        print(f"populated store with 1 enforced check for {subject.name} -> {args.store}")
        print(f"  next: checkseal seal-keyless --store {args.store} --subject {args.subject} \\")
        print(f"        --name {args.name} --kind harness_config --out harness-config.sigstore.json")
    print(f"  subject (config) sha256 : {subject_digest}")
    print(f"  == report config_sha256 : {config_sha}")
    print(f"  enforced_proof report   : {report_digest[:16]}...  threat_class={threat_class}  ees={ees}")


def _refuse_unless(condition: bool, why: str) -> None:
    if not condition:
        raise SystemExit(f"refusing to seal: {why}")


if __name__ == "__main__":
    main()
