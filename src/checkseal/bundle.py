"""Subject identity for agent tooling: directory bundles and archives.

Registry poisoning makes names untrusted, so an agent-tooling subject is
identified by bytes, never by a registry name. Two forms:

* A directory-shaped bundle (a skill with a ``SKILL.md``, an Agent Plugin with
  a ``plugin.json``) is identified by its **canonical content manifest**: sorted
  posix-relative paths (NFC-normalized) mapped to per-file sha256, serialized
  canonically. The manifest JSON is itself the subject artifact — publishable,
  per-file inspectable, and recomputable by any verifier from the installed tree.
* An archive-shaped distribution (a ``.mcpb`` zip, an npm/PyPI artifact) is
  identified by the sha256 of its exact bytes as distributed.

Unlike a harness config (where docs are excluded from identity), NOTHING
human-readable is excluded here beyond filesystem noise: every file in a skill
bundle is model-readable behavior — a README is prompt-injectable content — so
docs are identity. For the same reason a bare ``.pyc`` is identity (it is
importable behavior); only ``__pycache__/`` is excluded, because its contents
are derived from sources the manifest already covers.

Symlinks are REFUSED in v0.1, fail-closed: a symlinked directory is invisible
to a naive walk (content the model can reach would be absent from identity),
and a link out of the tree makes the digest depend on out-of-tree state. A
bundle that needs a link must ship real files.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

from .digest import canonical_bytes, sha256_file, sha256_hex
from .model import VCRError

# Filesystem noise only. Deliberately NOT excluded: README/docs and bare .pyc
# files (see module doc).
_EXCLUDE_NAMES = {".DS_Store"}
_EXCLUDE_DIRS = {".git", "__pycache__"}


def canonical_manifest(root: str | Path) -> tuple[bytes, str]:
    """Return (manifest_bytes, sha256_hex) for a directory-shaped bundle.

    The manifest maps each posix relative path (NFC-normalized, so the digest
    does not depend on the producer's filesystem normalization) to the sha256
    of that file's bytes; serialization is the library-wide canonical encoding,
    so the digest is reproducible from the tree alone, independent of machine
    paths. Any symlink in the tree raises VCRError (see module doc).
    """
    base = Path(root).resolve()
    if not base.is_dir():
        raise VCRError(f"bundle root is not a directory: {base}")
    manifest: dict[str, str] = {}
    for p in sorted(base.rglob("*")):
        rel = p.relative_to(base)
        if any(part in _EXCLUDE_DIRS for part in rel.parts):
            continue
        if p.is_symlink():
            raise VCRError(
                f"bundle contains a symlink ({rel.as_posix()}); symlinks are refused — "
                "identity must cover exactly the tree's own bytes, and a symlinked "
                "directory would hide reachable content from the manifest"
            )
        if not p.is_file() or p.name in _EXCLUDE_NAMES:
            continue
        key = unicodedata.normalize("NFC", rel.as_posix())
        if key in manifest:
            raise VCRError(
                f"bundle has two files whose paths NFC-normalize to {key!r}; refusing an ambiguous identity"
            )
        try:
            manifest[key] = sha256_file(str(p))
        except OSError as exc:
            raise VCRError(f"bundle file {rel.as_posix()} became unreadable: {exc}") from exc
    if not manifest:
        raise VCRError(f"bundle at {base} has no content files; refusing an empty identity")
    raw = canonical_bytes(manifest)
    return raw, sha256_hex(raw)


def archive_digest(path: str | Path) -> str:
    """The identity of an archive-shaped distribution: sha256 of its exact bytes."""
    return sha256_file(str(path))
