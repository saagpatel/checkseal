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
    reexecutor = _build_reexecutor(args.reexec) if args.reexec else None
    loader = _build_loader(args.proof_root)

    report = verify_local_seal(
        args.seal,
        verifier,
        subject_path=args.subject,
        reexecutor=reexecutor,
        loader=loader,
    )
    print(report.render())
    return 0 if report.ok else 1


def _build_reexecutor(command: str):
    """Real re-executor: run COMMAND for each enforced Grade-A check; exit 0 = confirmed.

    The check id and config_ref are passed in the environment so COMMAND can
    re-run the actual gate. There is deliberately no stub that always confirms.
    """
    import os
    import shlex
    import subprocess

    argv = shlex.split(command)

    def reexecute(entry) -> bool:
        env = {
            **os.environ,
            "CHECKSEAL_CHECK_ID": entry.check.id,
            "CHECKSEAL_CONFIG_REF": entry.check.config_ref or "",
        }
        return subprocess.run(argv, env=env, capture_output=True).returncode == 0

    return reexecute


def _build_loader(proof_root: str | None):
    if not proof_root:
        return default_report_loader

    import os

    from .hbresolve import ProofError

    root = os.path.realpath(proof_root)

    def loader(uri: str) -> bytes:
        cand = uri[len("file://") :] if uri.startswith("file://") else uri
        full = os.path.realpath(cand if os.path.isabs(cand) else os.path.join(root, cand))
        if full != root and not full.startswith(root + os.sep):
            raise ProofError(f"enforced_proof path escapes --proof-root: {uri!r}")
        return default_report_loader(full)

    return loader


def _cmd_seal_keyless(args: argparse.Namespace) -> int:
    from .seal import sign_keyless

    subject = Subject(
        kind=SubjectKind(args.kind).value,
        digest=sha256_file(args.subject),
        name=args.name,
        media_type=args.media_type,
    )
    predicate = assemble(JsonlSealStore(args.store), subject)
    seal = sign_keyless(predicate, identity_token=args.identity_token)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(seal.bundle_json or "")
    print(f"keyless-sealed {len(predicate.checks)} check(s) for {subject.name} -> {args.out}")
    return 0


def _cmd_verify_keyless(args: argparse.Namespace) -> int:
    from .verify import verify_keyless_seal

    with open(args.seal, encoding="utf-8") as fh:
        bundle = fh.read()
    report = verify_keyless_seal(
        bundle,
        expected_identity=args.identity,
        expected_issuer=args.issuer,
        subject_path=args.subject,
        reexecutor=_build_reexecutor(args.reexec) if args.reexec else None,
        loader=_build_loader(args.proof_root),
        max_age_seconds=args.max_age,
    )
    print(report.render())
    return 0 if report.ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="checkseal", description="emit and verify AI-artifact check receipts")
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
        "--reexec",
        default=None,
        metavar="CMD",
        help="command to re-run each enforced Grade-A gate; exit 0 = confirmed "
        "(CHECKSEAL_CHECK_ID / CHECKSEAL_CONFIG_REF in env)",
    )
    vf.add_argument("--proof-root", default=None, help="resolve enforced_proof URIs confined under this dir")
    vf.set_defaults(func=_cmd_verify)

    slk = sub.add_parser("seal-keyless", help="seal for a public T2 seal via Sigstore keyless (CI/OIDC)")
    slk.add_argument("--store", required=True)
    slk.add_argument("--subject", required=True)
    slk.add_argument("--name", required=True)
    slk.add_argument("--kind", default="artifact", choices=[k.value for k in SubjectKind])
    slk.add_argument("--media-type", default=None)
    slk.add_argument("--identity-token", default=None, help="OIDC token; omitted = ambient CI credential")
    slk.add_argument("--out", required=True, help="output Sigstore bundle (.sigstore.json)")
    slk.set_defaults(func=_cmd_seal_keyless)

    vk = sub.add_parser("verify-keyless", help="verify a T2 .sigstore.json seal (full contract)")
    vk.add_argument("seal")
    vk.add_argument("--subject", required=True)
    vk.add_argument("--identity", required=True, help="expected OIDC identity (SAN)")
    vk.add_argument("--issuer", required=True, help="expected OIDC issuer")
    vk.add_argument("--reexec", default=None, metavar="CMD")
    vk.add_argument("--proof-root", default=None)
    vk.add_argument("--max-age", type=int, default=None, help="freshness bound in seconds (Rekor not-after)")
    vk.set_defaults(func=_cmd_verify_keyless)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
