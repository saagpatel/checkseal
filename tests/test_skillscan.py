"""The scanner→sealer path (docs/skillscan-report-v1.md): untrusted report in, honest seal out."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from checkseal.bundle import canonical_manifest
from checkseal.digest import sha256_hex
from checkseal.model import VCRError
from checkseal.profile_agent_tooling import (
    BUNDLE_MANIFEST_MEDIA_TYPE,
    validate_agent_tooling_profile,
)
from checkseal.skillscan import seed_from_report

FIXTURE_BUNDLE = Path(__file__).parent / "fixtures" / "agent-tooling" / "skill-demo"

RULESET_SHA = sha256_hex(b"ruleset")


def make_report(**over) -> bytes:
    _, digest = canonical_manifest(FIXTURE_BUNDLE)
    base = {
        "schema": "skillscan-report/v1",
        "scanner": "mcp-audit",
        "scanner_version": "2.8.0",
        "ran_at": "2026-08-24T00:00:00Z",
        "subject": {
            "kind": "skill_bundle",
            "name": "skill/demo-summarizer@fixture",
            "digest": digest,
            "media_type": BUNDLE_MANIFEST_MEDIA_TYPE,
        },
        "ruleset": {"config_sha256": RULESET_SHA, "rules": ["SKILL001"]},
        "checks": [
            {"id": "scan/injection-patterns", "result": "pass", "findings": 0, "detail": []},
            {"id": "scan/dynamic-fetch-presence", "result": "pass", "findings": 0, "detail": []},
        ],
    }
    base.update(over)
    return json.dumps(base).encode("utf-8")


def test_seed_builds_profile_valid_predicate():
    seed = seed_from_report(make_report(), FIXTURE_BUNDLE)
    validate_agent_tooling_profile(seed.predicate, public=False)
    assert len(seed.predicate.checks) == 2
    entry = seed.predicate.checks[0]
    assert entry.check.config_ref == RULESET_SHA
    assert entry.evidence.digest == seed.report_digest  # evidence = the exact report bytes
    assert seed.manifest_bytes is not None


def test_report_with_wrong_digest_is_refused():
    _, digest = canonical_manifest(FIXTURE_BUNDLE)
    subject = {
        "kind": "skill_bundle",
        "name": "skill/demo-summarizer@fixture",
        "digest": "f" * 64,  # claims different bytes were scanned
        "media_type": BUNDLE_MANIFEST_MEDIA_TYPE,
    }
    with pytest.raises(VCRError, match="REFUSED"):
        seed_from_report(make_report(subject=subject), FIXTURE_BUNDLE)
    assert digest != "f" * 64


def test_report_with_skip_result_is_rejected_at_parse():
    report = make_report(
        checks=[{"id": "scan/injection-patterns", "result": "skip", "findings": 0, "detail": []}]
    )
    with pytest.raises(VCRError, match="skip"):
        seed_from_report(report, FIXTURE_BUNDLE)


def test_runtime_namespace_in_report_is_rejected_by_profile():
    report = make_report(
        checks=[{"id": "runtime/observed-egress", "result": "pass", "findings": 0, "detail": []}]
    )
    seed = seed_from_report(report, FIXTURE_BUNDLE)  # parse is shape-only...
    with pytest.raises(VCRError, match="reserved"):  # ...the profile holds the line
        validate_agent_tooling_profile(seed.predicate, public=False)


def test_cli_seal_skillscan_end_to_end(tmp_path, local_signer):
    from checkseal.__main__ import main
    from checkseal.sign.local import write_private_pem, write_public_pem

    key, pub = tmp_path / "k.pem", tmp_path / "k.pub.pem"
    write_private_pem(local_signer, str(key))
    write_public_pem(local_signer, str(pub))

    report_path = tmp_path / "report.json"
    report_path.write_bytes(make_report())
    manifest_out = tmp_path / "subject.manifest.json"
    seal_out = tmp_path / "seal.intoto.jsonl"

    rc = main(
        [
            "seal-skillscan",
            "--report",
            str(report_path),
            "--bundle",
            str(FIXTURE_BUNDLE),
            "--store",
            str(tmp_path / "t0.jsonl"),
            "--manifest-out",
            str(manifest_out),
            "--key",
            str(key),
            "--out",
            str(seal_out),
        ]
    )
    assert rc == 0
    # The written manifest is the subject artifact: the stock verifier closes the loop.
    rc = main(["verify", str(seal_out), "--subject", str(manifest_out), "--pubkey", str(pub)])
    assert rc == 0


def test_cli_refuses_drifted_bundle(tmp_path, capsys):
    import shutil

    from checkseal.__main__ import main

    drifted = tmp_path / "skill-demo"
    shutil.copytree(FIXTURE_BUNDLE, drifted)
    (drifted / "SKILL.md").write_text("changed after the scan\n")

    report_path = tmp_path / "report.json"
    report_path.write_bytes(make_report())  # digest of the ORIGINAL fixture

    rc = main(
        [
            "seal-skillscan",
            "--report",
            str(report_path),
            "--bundle",
            str(drifted),
            "--store",
            str(tmp_path / "t0.jsonl"),
        ]
    )
    assert rc == 1
    assert "refused" in capsys.readouterr().err


def test_archive_form_seeds_and_validates(tmp_path):
    import zipfile

    from checkseal.bundle import archive_digest

    mcpb = tmp_path / "demo.mcpb"
    with zipfile.ZipFile(mcpb, "w") as zf:
        zf.writestr("manifest.json", "{}")
    report = make_report(
        subject={
            "kind": "mcp_server",
            "name": "mcp-server/demo@1.0.0",
            "digest": archive_digest(mcpb),
            "media_type": "application/vnd.mcpb+zip",
        }
    )
    seed = seed_from_report(report, mcpb)
    validate_agent_tooling_profile(seed.predicate, public=False)
    assert seed.manifest_bytes is None  # archives have no manifest form
