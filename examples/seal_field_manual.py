"""Produce a real, honest CheckSeal for the operator's Field Manual.

This is a worked example on a REAL artifact with REAL evidence: the vendored
Field Manual source, its publication-rights record (a rights-gate verdict bound
to the artifact's exact sha256), and the upstream provenance ledger the record
cites. Both checks are ADVISORY (they are human/review attestations, not
mechanically-enforced gates), so no enforced_proof is claimed and nothing is
over-stated. Paths are arguments, so no local paths are baked into the repo.

    python examples/seal_field_manual.py \
        --subject <field-manual.md> --name field-manual \
        --rights <field-manual-publication-rights.json> \
        --key <t1-key.pem> --store /tmp/fm.jsonl --out field-manual.intoto.jsonl

The rights record supplies the provenance-ledger digest (its upstream_evidence
.ledger_sha256), so the provenance check's evidence is the operator's own ledger.
"""

from __future__ import annotations

import argparse
import json

from checkseal.digest import sha256_file, sha256_hex
from checkseal.model import (
    Authority,
    Check,
    CheckEntry,
    CheckKind,
    Enforced,
    Evidence,
    EvidenceKind,
    Predicate,
    Provenance,
    Result,
    Runner,
    Runtime,
    Subject,
    SubjectKind,
)
from checkseal.seal import sign_local
from checkseal.sign.local import load_private_signer
from checkseal.store import CheckResult, JsonlSealStore


def build(subject_path: str, name: str, rights_path: str, as_of: str) -> Subject:
    return Subject(kind=SubjectKind.ARTIFACT.value, digest=sha256_file(subject_path), name=name)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--rights", required=True, help="field-manual-publication-rights.json")
    ap.add_argument("--key", required=True)
    ap.add_argument("--store", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rights = json.load(open(args.rights, encoding="utf-8"))
    as_of = str(rights.get("as_of", "2026-08-05"))
    ledger_sha = rights["upstream_evidence"]["ledger_sha256"]
    # Sanity: the rights record must actually be about this artifact.
    subject_digest = sha256_file(args.subject)
    if rights["artifact"]["sha256"] != subject_digest:
        raise SystemExit(
            f"rights record is about {rights['artifact']['sha256'][:12]}..., "
            f"but subject is {subject_digest[:12]}... - refusing to seal a mismatched claim"
        )

    subject = Subject(kind=SubjectKind.ARTIFACT.value, digest=subject_digest, name=args.name)

    rights_gate = CheckEntry(
        check=Check(id="review/rights-gate", kind=CheckKind.HUMAN, version="v2"),
        verdict=Verdict_pass(),  # publication AUTHORIZED, MIT, operator consent recorded
        evidence=Evidence(kind=EvidenceKind.LOG_DIGEST, grade=Grade_B(), digest=sha256_file(args.rights)),
        runtime=Runtime(ran_at=as_of + "T00:00:00Z", runner=Runner.HUMAN),
        provenance=Provenance(authority=Authority.OPERATOR),
    )
    provenance = CheckEntry(
        check=Check(id="review/provenance-ledger", kind=CheckKind.HUMAN, version="v1"),
        verdict=Verdict_pass(),
        evidence=Evidence(kind=EvidenceKind.LOG_DIGEST, grade=Grade_B(), digest=ledger_sha),
        runtime=Runtime(ran_at=as_of + "T00:00:00Z", runner=Runner.HUMAN),
        provenance=Provenance(authority=Authority.OPERATOR),
    )

    store = JsonlSealStore(args.store)
    store.append(CheckResult(subject, rights_gate))
    store.append(CheckResult(subject, provenance))

    from checkseal.seal import assemble

    predicate = assemble(store, subject)
    signer = load_private_signer(args.key)
    seal = sign_local(predicate, signer, public=False)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(seal.to_intoto_jsonl() + "\n")
    print(f"sealed {len(predicate.checks)} real checks for {name_of(subject)} -> {args.out}")
    print(
        f"subject sha256 {subject_digest[:16]}...  rights digest {sha256_hex(open(args.rights, 'rb').read())[:16]}..."
    )


def name_of(s: Subject) -> str:
    return s.name


def Verdict_pass():
    from checkseal.model import Verdict

    return Verdict(result=Result.PASS, enforced=Enforced.ADVISORY)


def Grade_B():
    from checkseal.model import Grade

    return Grade.B


if __name__ == "__main__":
    main()
