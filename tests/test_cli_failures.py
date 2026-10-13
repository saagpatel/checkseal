from __future__ import annotations

import sys

from checkseal.__main__ import main
from checkseal.sign.local import write_public_pem
from conftest import write_hb_report
from test_end_to_end import _seal_two_checks


def test_skillscan_rejects_unpaired_key_and_output(capsys):
    result = main(
        [
            "seal-skillscan",
            "--report",
            "missing.json",
            "--bundle",
            "missing-bundle",
            "--store",
            "store.jsonl",
            "--key",
            "key.pem",
        ]
    )
    assert result != 0
    assert "--key and --out must be supplied together" in capsys.readouterr().err


def test_reexecution_timeout_is_failed_and_includes_stderr_tail(tmp_path, local_signer, monkeypatch, capsys):
    import checkseal.__main__ as cli

    monkeypatch.setattr(cli, "REEXEC_TIMEOUT_SECONDS", 0.2)
    proof = write_hb_report(tmp_path / "hb.json")
    subject, seal = _seal_two_checks(tmp_path, local_signer, proof)
    public_key = tmp_path / "public.pem"
    write_public_pem(local_signer, str(public_key))
    command = (
        f"{sys.executable} -c 'import sys,time; "
        "sys.stderr.write(str(123456)); sys.stderr.flush(); time.sleep(2)'"
    )
    result = main(
        [
            "verify",
            str(seal),
            "--subject",
            str(subject),
            "--pubkey",
            str(public_key),
            "--reexec",
            command,
            "--proof-root",
            str(tmp_path),
        ]
    )
    assert result != 0
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "FAILED (TimeoutError" in output
    assert "123456" in output
