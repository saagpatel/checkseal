"""Conformance cases for the agent-tooling profile (docs/profile-agent-tooling.md).

Hand-built records over committed fixtures — no scanner dependency. The worked
examples in the spec show digests computed from ``tests/fixtures/agent-tooling``;
``test_spec_example_digest_is_reproducible`` keeps spec and fixtures in lock-step.
"""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest

from checkseal.bundle import archive_digest, canonical_manifest
from checkseal.model import (
    CheckKind,
    Enforced,
    EvidenceKind,
    Grade,
    Predicate,
    Result,
    Subject,
    VCRError,
)
from checkseal.profile_agent_tooling import (
    BUNDLE_MANIFEST_MEDIA_TYPE,
    MCPB_MEDIA_TYPE,
    validate_agent_tooling_profile,
)
from checkseal.seal import sign_local
from checkseal.verify import verify_local_seal
from conftest import VALID_SHA, make_entry

FIXTURE_BUNDLE = Path(__file__).parent / "fixtures" / "agent-tooling" / "skill-demo"


def scan_entry(**overrides):
    """A well-formed agent-tooling scan check entry."""
    defaults = dict(
        check_id="scan/injection-patterns",
        kind=CheckKind.REVIEW,
        enforced=Enforced.OBSERVED,
        grade=Grade.A,
        result=Result.PASS,
        evidence_kind=EvidenceKind.LOG_DIGEST,
        config_ref=VALID_SHA,
    )
    defaults.update(overrides)
    return make_entry(**defaults)


def bundle_subject(name: str = "skill/demo-summarizer@fixture") -> tuple[Subject, bytes]:
    manifest_bytes, digest = canonical_manifest(FIXTURE_BUNDLE)
    return (
        Subject(
            kind="skill_bundle",
            digest=digest,
            name=name,
            media_type=BUNDLE_MANIFEST_MEDIA_TYPE,
        ),
        manifest_bytes,
    )


def seal_to_path(predicate: Predicate, signer, tmp_path: Path) -> Path:
    seal = sign_local(predicate, signer, public=False)
    path = tmp_path / "seal.intoto.jsonl"
    path.write_text(seal.to_intoto_jsonl() + "\n")
    return path


# --- happy paths ------------------------------------------------------------


def test_well_formed_skill_bundle_seal_verifies(tmp_path, local_signer):
    subject, manifest_bytes = bundle_subject()
    predicate = Predicate(subject=subject, checks=[scan_entry()])
    validate_agent_tooling_profile(predicate, public=False)

    seal_path = seal_to_path(predicate, local_signer, tmp_path)
    report = verify_local_seal(str(seal_path), local_signer.verifier(), subject_bytes=manifest_bytes)
    assert report.ok, report.render()
    assert report.entries[0].trust_floor == 0  # observed: telemetry only, never more


def test_mcpb_archive_subject_verifies(tmp_path, local_signer):
    # A deterministic .mcpb-shaped zip built in-test (no committed binaries).
    mcpb = tmp_path / "demo.mcpb"
    with zipfile.ZipFile(mcpb, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("manifest.json", date_time=(2026, 1, 1, 0, 0, 0))
        zf.writestr(info, json.dumps({"name": "demo-server", "version": "1.0.0"}))
    subject = Subject(
        kind="mcp_server",
        digest=archive_digest(mcpb),
        name="mcp-server/demo-server@1.0.0",
        media_type=MCPB_MEDIA_TYPE,
    )
    predicate = Predicate(subject=subject, checks=[scan_entry()])
    validate_agent_tooling_profile(predicate, public=False)

    seal_path = seal_to_path(predicate, local_signer, tmp_path)
    report = verify_local_seal(str(seal_path), local_signer.verifier(), subject_path=str(mcpb))
    assert report.ok, report.render()


# --- identity: bytes, not names --------------------------------------------


def test_forged_subject_digest_fails_authentic(tmp_path, local_signer):
    _, manifest_bytes = bundle_subject()
    forged = Subject(
        kind="artifact",
        digest="0" * 64,  # claims an identity the bytes do not have
        name="skill/demo-summarizer@fixture",
        media_type=BUNDLE_MANIFEST_MEDIA_TYPE,
    )
    predicate = Predicate(subject=forged, checks=[scan_entry()])
    seal_path = seal_to_path(predicate, local_signer, tmp_path)
    report = verify_local_seal(str(seal_path), local_signer.verifier(), subject_bytes=manifest_bytes)
    assert not report.subject_digest_ok
    assert not report.authentic
    assert not report.ok


def test_bytes_drift_breaks_the_receipt(tmp_path, local_signer):
    """An updated skill gets a new digest and therefore no inherited receipt."""
    subject, _ = bundle_subject()
    predicate = Predicate(subject=subject, checks=[scan_entry()])
    seal_path = seal_to_path(predicate, local_signer, tmp_path)

    drifted = tmp_path / "skill-demo"
    shutil.copytree(FIXTURE_BUNDLE, drifted)
    (drifted / "SKILL.md").write_text((drifted / "SKILL.md").read_text() + "\nInjected sentence.\n")
    drifted_bytes, drifted_digest = canonical_manifest(drifted)
    assert drifted_digest != subject.digest

    report = verify_local_seal(str(seal_path), local_signer.verifier(), subject_bytes=drifted_bytes)
    assert not report.subject_digest_ok
    assert not report.ok


def test_no_live_subject_fails_closed(tmp_path, local_signer):
    subject, _ = bundle_subject()
    predicate = Predicate(subject=subject, checks=[scan_entry()])
    seal_path = seal_to_path(predicate, local_signer, tmp_path)
    report = verify_local_seal(str(seal_path), local_signer.verifier())
    assert not report.subject_digest_ok  # a seal in isolation proves a past state
    assert not report.ok
    assert not report.passes(authentic_only=True)  # the exit decision fails closed too


# --- profile rejections -----------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"enforced": Enforced.ENFORCED}, "unprovable"),
        ({"check_id": "runtime/observed-egress", "kind": CheckKind.GUARD}, "reserved"),
        ({"check_id": "review/editorial"}, "namespace"),
        ({"result": Result.SKIP}, "skip"),
        ({"result": Result.NA}, "not attempted"),
        ({"result": Result.OVER_BLOCKED}, "ground-truth"),
        ({"grade": Grade.C, "evidence_kind": EvidenceKind.REVIEWER_ID}, "grade C"),
        ({"config_ref": None}, "config_ref"),
        ({"kind": CheckKind.HUMAN}, "review"),
        # Plain strings where enums are expected (a producer building dataclasses
        # straight from scanner JSON) must not slip past the prohibitions.
        ({"enforced": "enforced"}, "unprovable"),
        ({"result": "skip"}, "skip"),
        ({"result": "n/a"}, "not attempted"),
        ({"kind": "human"}, "review"),
    ],
)
def test_profile_rejects(overrides, fragment):
    subject, _ = bundle_subject()
    predicate = Predicate(subject=subject, checks=[scan_entry(**overrides)])
    with pytest.raises(VCRError, match=fragment):
        validate_agent_tooling_profile(predicate, public=False)


def test_profile_requires_artifact_kind_and_media_type():
    digest = canonical_manifest(FIXTURE_BUNDLE)[1]
    wrong_kind = Subject(
        kind="harness_config", digest=digest, name="skill/x", media_type=BUNDLE_MANIFEST_MEDIA_TYPE
    )
    with pytest.raises(VCRError, match="subject.kind"):
        validate_agent_tooling_profile(Predicate(subject=wrong_kind, checks=[scan_entry()]), public=False)
    no_media = Subject(kind="skill_bundle", digest=digest, name="skill/x")
    with pytest.raises(VCRError, match="mediaType"):
        validate_agent_tooling_profile(Predicate(subject=no_media, checks=[scan_entry()]), public=False)
    # Pre-delta records minted with the generic kind stay valid.
    pre_delta = Subject(kind="artifact", digest=digest, name="skill/x", media_type=BUNDLE_MANIFEST_MEDIA_TYPE)
    validate_agent_tooling_profile(Predicate(subject=pre_delta, checks=[scan_entry()]), public=False)


def test_profile_composes_with_n1():
    """An agent-tooling seal cannot bypass N1: zero checks is still refused."""
    subject, _ = bundle_subject()
    with pytest.raises(VCRError, match="at least one check"):
        validate_agent_tooling_profile(Predicate(subject=subject, checks=[]), public=False)


# --- error is not clean -----------------------------------------------------


def test_scanner_failure_renders_as_error_never_clean(tmp_path, local_signer):
    subject, manifest_bytes = bundle_subject()
    predicate = Predicate(subject=subject, checks=[scan_entry(result=Result.ERROR)])
    validate_agent_tooling_profile(predicate, public=False)  # error is emittable...

    seal_path = seal_to_path(predicate, local_signer, tmp_path)
    report = verify_local_seal(str(seal_path), local_signer.verifier(), subject_bytes=manifest_bytes)
    assert report.authentic  # the seal honestly records a failure
    assert not report.checks_passed  # ...but it can never render as a pass
    assert not report.ok
    assert "result=error" in report.render()


# --- freshness (T2 policy function; no network) -----------------------------


def test_stale_seal_fails_closed():
    from checkseal.verify import _freshness

    bundle = json.dumps({"verificationMaterial": {"tlogEntries": [{"integratedTime": 1_000_000}]}})
    ok, reason = _freshness(bundle, max_age_seconds=86_400, now=1_000_000 + 200_000)
    assert not ok
    assert "STALE" in reason

    ok, reason = _freshness("{}", max_age_seconds=86_400, now=None)
    assert not ok  # unreadable log time under a requested bound fails closed


# --- canonical manifest -----------------------------------------------------


def test_canonical_manifest_is_deterministic_and_docs_are_identity():
    first_bytes, first_digest = canonical_manifest(FIXTURE_BUNDLE)
    second_bytes, second_digest = canonical_manifest(FIXTURE_BUNDLE)
    assert first_bytes == second_bytes
    assert first_digest == second_digest

    manifest = json.loads(first_bytes)
    assert "SKILL.md" in manifest  # docs are prompt-injectable, so docs are identity
    assert "scripts/summarize.py" in manifest


def test_canonical_manifest_excludes_noise_only(tmp_path):
    root = tmp_path / "bundle"
    (root / ".git").mkdir(parents=True)
    (root / "__pycache__").mkdir()
    root.joinpath("SKILL.md").write_text("skill\n")
    root.joinpath("README.md").write_text("readme\n")
    root.joinpath(".DS_Store").write_bytes(b"noise")
    root.joinpath("payload.pyc").write_bytes(b"bytecode")
    root.joinpath(".git", "config").write_text("noise\n")
    root.joinpath("__pycache__", "mod.cpython-312.pyc").write_bytes(b"noise")

    manifest = json.loads(canonical_manifest(root)[0])
    # A bare .pyc is importable behavior, so it IS identity; __pycache__ is
    # derived from sources the manifest already covers, so it is not.
    assert set(manifest) == {"SKILL.md", "README.md", "payload.pyc"}


def test_canonical_manifest_refuses_symlinks(tmp_path):
    """A symlinked dir hides reachable content from a naive walk; refuse, fail closed."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "inject.md").write_text("payload\n")

    linked_dir = tmp_path / "bundle-dir"
    linked_dir.mkdir()
    (linked_dir / "SKILL.md").write_text("skill\n")
    (linked_dir / "lib").symlink_to(outside, target_is_directory=True)
    with pytest.raises(VCRError, match="symlink"):
        canonical_manifest(linked_dir)

    linked_file = tmp_path / "bundle-file"
    linked_file.mkdir()
    (linked_file / "SKILL.md").write_text("skill\n")
    (linked_file / "extra.md").symlink_to(outside / "inject.md")
    with pytest.raises(VCRError, match="symlink"):
        canonical_manifest(linked_file)

    dangling = tmp_path / "bundle-dangling"
    dangling.mkdir()
    (dangling / "SKILL.md").write_text("skill\n")
    (dangling / "later.md").symlink_to(dangling / "not-yet-there")
    with pytest.raises(VCRError, match="symlink"):
        canonical_manifest(dangling)


def test_canonical_manifest_normalizes_unicode_paths(tmp_path):
    """NFD and NFC spellings of the same logical path digest identically."""
    import unicodedata

    nfc = tmp_path / "nfc"
    nfc.mkdir()
    (nfc / "SKILL.md").write_text("skill\n")
    (nfc / unicodedata.normalize("NFC", "café.md")).write_text("same\n")
    nfd = tmp_path / "nfd"
    nfd.mkdir()
    (nfd / "SKILL.md").write_text("skill\n")
    (nfd / unicodedata.normalize("NFD", "café.md")).write_text("same\n")

    nfc_manifest, nfc_digest = canonical_manifest(nfc)
    _, nfd_digest = canonical_manifest(nfd)
    assert unicodedata.normalize("NFC", "café.md") in json.loads(nfc_manifest)
    assert nfc_digest == nfd_digest


def test_empty_bundle_is_refused(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(VCRError, match="empty"):
        canonical_manifest(empty)


def test_spec_example_digest_is_reproducible():
    """docs/profile-agent-tooling.md shows this exact digest; keep them in lock-step."""
    spec = (Path(__file__).parent.parent / "docs" / "profile-agent-tooling.md").read_text(encoding="utf-8")
    manifest_bytes, digest = canonical_manifest(FIXTURE_BUNDLE)
    assert manifest_bytes.decode("utf-8") in spec, (
        "the spec's worked-example manifest JSON no longer matches the committed fixture"
    )
    assert digest in spec, (
        "the spec's worked-example digest no longer matches the committed fixture; "
        f"recompute and update docs/profile-agent-tooling.md to {digest}"
    )
