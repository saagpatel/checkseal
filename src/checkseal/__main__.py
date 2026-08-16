"""checkseal CLI.

    checkseal keygen   --out KEY.pem
    checkseal seal     --store S.jsonl --subject FILE --name NAME --key KEY.pem --out SEAL
    checkseal verify   SEAL --subject FILE --pubkey PUB.pem [--reexec-ok] [--proof-root DIR]

The verifier is the contract; ``verify`` exits non-zero if the seal does not
pass. T2 keyless seal/verify live behind the keyless extra and CI (they need an
OIDC credential); this CLI covers the offline T1 path end to end.
"""

from __future__ import annotations

import argparse
import sys

from .digest import sha256_file
from .hbresolve import default_report_loader
from .model import Subject, SubjectKind
from .seal import assemble, sign_local
from .store import JsonlSealStore
from .verify import verify_local_seal


def _cmd_keygen(args: argparse.Namespace) -> int:
    from .sign.local import LocalKeySigner, write_private_pem, write_public_pem

    signer = LocalKeySigner.generate()
    write_private_pem(signer, args.out)
    if args.pub:
        write_public_pem(signer, args.pub)
    print(f"wrote T1 private key {args.out} (keyid {signer.keyid})")
    return 0


def _cmd_seal(args: argparse.Namespace) -> int:
    from .sign.local import load_private_signer

    subject = Subject(
        kind=SubjectKind(args.kind).value,
        digest=sha256_file(args.subject),
        name=args.name,
        media_type=args.media_type,
    )
    store = JsonlSealStore(args.store)
    predicate = assemble(store, subject)
    signer = load_private_signer(args.key)
    seal = sign_local(predicate, signer, public=False)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(seal.to_intoto_jsonl() + "\n")
    print(f"sealed {len(predicate.checks)} check(s) for {subject.name} -> {args.out}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from .sign.local import load_public_verifier

    verifier = load_public_verifier(args.pubkey)

    reexecutor = None
    if args.reexec_ok:
        reexecutor = lambda _entry: True  # noqa: E731 - test/demo confirmer

    loader = default_report_loader
    if args.proof_root:
        root = args.proof_root.rstrip("/")

        def loader(uri: str) -> bytes:  # noqa: F811 - rebind for rooted proofs
            path = uri if uri.startswith("/") else f"{root}/{uri}"
            return default_report_loader(path)

    report = verify_local_seal(
        args.seal,
        verifier,
        subject_path=args.subject,
        reexecutor=reexecutor,
        loader=loader,
    )
    print(report.render())
    return 0 if report.ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="checkseal", description="emit and verify AI-artifact check receipts"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="generate a T1 local Ed25519 key")
    kg.add_argument("--out", required=True)
    kg.add_argument("--pub", help="also write the public key here")
    kg.set_defaults(func=_cmd_keygen)

    sl = sub.add_parser("seal", help="seal stored check-results for one subject (T1)")
    sl.add_argument("--store", required=True)
    sl.add_argument("--subject", required=True, help="path to the artifact being sealed")
    sl.add_argument("--name", required=True)
    sl.add_argument("--kind", default="artifact", choices=[k.value for k in SubjectKind])
    sl.add_argument("--media-type", default=None)
    sl.add_argument("--key", required=True)
    sl.add_argument("--out", required=True)
    sl.set_defaults(func=_cmd_seal)

    vf = sub.add_parser("verify", help="verify a .intoto.jsonl seal against the Verifier Contract")
    vf.add_argument("seal")
    vf.add_argument("--subject", required=True, help="path to the live artifact")
    vf.add_argument("--pubkey", required=True)
    vf.add_argument(
        "--reexec-ok", action="store_true", help="stub re-executor that confirms (tests/demo)"
    )
    vf.add_argument("--proof-root", default=None, help="resolve enforced_proof URIs under this dir")
    vf.set_defaults(func=_cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
