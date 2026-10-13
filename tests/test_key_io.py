from __future__ import annotations

import os

import pytest

from checkseal.sign.local import LocalKeySigner, write_private_pem


def test_private_key_is_created_mode_0600(tmp_path):
    path = tmp_path / "private.pem"
    write_private_pem(LocalKeySigner.generate(), str(path))
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_private_key_refuses_existing_file(tmp_path):
    path = tmp_path / "private.pem"
    path.write_text("keep")
    with pytest.raises(FileExistsError):
        write_private_pem(LocalKeySigner.generate(), str(path))
    assert path.read_text() == "keep"


def test_private_key_refuses_symlink(tmp_path):
    target = tmp_path / "target.pem"
    target.write_text("keep")
    link = tmp_path / "private.pem"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        write_private_pem(LocalKeySigner.generate(), str(link))
    assert target.read_text() == "keep"
