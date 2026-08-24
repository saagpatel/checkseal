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
    print(report.render(authentic_only=args.authentic_only))
    return 0 if report.passes(authentic_only=args.authentic_only) else 1


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


def _cmd_seal_skillscan(args: argparse.Namespace) -> int:
    from .model import Authority, Runner, VCRError
    from .profile_agent_tooling import validate_agent_tooling_profile
    from .skillscan import seed_from_report
    from .store import CheckResult

    with open(args.report, "rb") as fh:
        report_bytes = fh.read()
    try:
        seed = seed_from_report(
            report_bytes,
            args.bundle,
            authority=Authority(args.authority),
            runner=Runner(args.runner),
        )
        validate_agent_tooling_profile(seed.predicate, public=False)
    except VCRError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1

    store = JsonlSealStore(args.store)
    for entry in seed.predicate.checks:
        store.append(CheckResult(seed.predicate.subject, entry))

    if seed.manifest_bytes is not None and args.manifest_out:
        with open(args.manifest_out, "wb") as fh:
            fh.write(seed.manifest_bytes)
        print(f"wrote canonical bundle manifest -> {args.manifest_out} (this file IS the subject)")

    n = len(seed.predicate.checks)
    subject = seed.predicate.subject
    if args.key and args.out:
        from .sign.local import load_private_signer

        seal = sign_local(seed.predicate, load_private_signer(args.key), public=False)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(seal.to_intoto_jsonl() + "\n")
        print(f"sealed {n} scan check(s) for {subject.name} ({subject.digest[:12]}...) -> {args.out}")
    else:
        print(
            f"stored {n} scan check(s) for {subject.name} ({subject.digest[:12]}...) in {args.store}; "
            "seal with 'checkseal seal' (T1) or 'checkseal seal-keyless' (public T2)"
        )
    return 0


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
    print(report.render(authentic_only=args.authentic_only))
    return 0 if report.passes(authentic_only=args.authentic_only) else 1


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
    vf.add_argument(
        "--authentic-only",
        action="store_true",
        help="pass if the seal is authentic (signed, digest-bound, trusted entries) even when "
        "some checks report a failing result; the honest verdict for an observed sitting",
    )
    vf.set_defaults(func=_cmd_verify)

    ssc = sub.add_parser(
        "seal-skillscan",
        help="ingest a skillscan-report/v1 over an agent skill / MCP server bundle (agent-tooling profile)",
    )
    ssc.add_argument("--report", required=True, help="the skillscan-report/v1 JSON from the scanner")
    ssc.add_argument(
        "--bundle",
        required=True,
        help="the scanned bundle (directory or archive); identity is recomputed from it",
    )
    ssc.add_argument("--store", required=True, help="T0 store to append the derived check-results to")
    ssc.add_argument(
        "--manifest-out",
        default=None,
        help="write the canonical bundle manifest here (directory form; this file is the subject artifact)",
    )
    ssc.add_argument("--key", default=None, help="T1 key; with --out, also seal immediately")
    ssc.add_argument("--out", default=None, help="output .intoto.jsonl seal (requires --key)")
    ssc.add_argument("--authority", default="agent", choices=["operator", "agent", "ingested"])
    ssc.add_argument("--runner", default="fleet", choices=["fleet", "ci", "human"])
    ssc.set_defaults(func=_cmd_seal_skillscan)

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
    vk.add_argument(
        "--authentic-only",
        action="store_true",
        help="pass if the seal is authentic (signed, digest-bound, fresh, trusted entries) even "
        "when some checks report a failing result; the honest verdict for an observed sitting",
    )
    vk.set_defaults(func=_cmd_verify_keyless)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
