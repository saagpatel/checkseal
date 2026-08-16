"""Resolve an ``enforced_proof`` against a HarnessBench report.

Verifier Contract step 4, with the N1 CONTRACT-DELTA: it is not enough that the
HarnessBench record exists and covers check.id@config_ref. The corpus's threat
class must match the check's semantic class, or the proof is rendered "gate
unproven (corpus mismatch)". A destructive-execution corpus does NOT prove a
content rights-gate; treating it as if it did is exactly the over-claim
CheckSeal exists to prevent.

Two asks of HarnessBench (N2) make this a strong, cryptographic binding rather
than a name-and-class binding (see DESIGN.md CONTRACT-DELTA):
  (a) declare ``threat_class`` on each report;
  (b) declare the subject config's ``config_sha256`` on each report,
      so a check's ``config_ref.sha256`` binds to a specific measured config.
Until then this resolver infers the class from the corpus name and binds by
subject name, and says so in the reason string.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .digest import sha256_hex
from .model import CheckEntry, EnforcedProof

# A report loader takes a URI and returns raw bytes. Injectable for tests and to
# keep the verifier offline-first (default handles local paths and file://).
ReportLoader = Callable[[str], bytes]


def default_report_loader(uri: str) -> bytes:
    path = uri[len("file://") :] if uri.startswith("file://") else uri
    if path.startswith(("http://", "https://")):
        raise ProofError("remote enforced_proof fetch is not enabled in the offline verifier")
    with open(path, "rb") as fh:
        return fh.read()


class ProofError(ValueError):
    pass


@dataclass(frozen=True)
class ProofResolution:
    resolved: bool
    reason: str
    corpus: str | None = None
    threat_class: str | None = None
    ees: float | None = None
    strong_binding: bool = False  # True only when config_sha256 is declared and matches


def _infer_threat_class(corpus: str) -> str:
    # "asi05-destructive-execution" -> "destructive-execution"
    parts = corpus.split("-", 1)
    if len(parts) == 2 and parts[0].startswith("asi") and parts[0][3:].isdigit():
        return parts[1]
    return corpus


def _check_threat_class(entry: CheckEntry) -> str:
    # Convention: the last path segment of check.id names the threat class.
    return entry.check.id.rsplit("/", 1)[-1]


def resolve_enforced_proof(
    entry: CheckEntry,
    proof: EnforcedProof,
    *,
    loader: ReportLoader = default_report_loader,
) -> ProofResolution:
    try:
        raw = loader(proof.uri)
    except (OSError, ProofError) as exc:
        return ProofResolution(False, f"proof unresolvable: {exc}")

    if sha256_hex(raw) != proof.sha256:
        return ProofResolution(
            False, "gate unproven: proof content digest does not match enforced_proof.sha256"
        )

    try:
        report: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError as exc:
        return ProofResolution(False, f"gate unproven: proof is not valid JSON ({exc})")

    schema = str(report.get("schema", ""))
    if not schema.startswith("harnessbench-report/"):
        return ProofResolution(
            False, f"gate unproven: not a HarnessBench report (schema={schema!r})"
        )

    corpus = str(report.get("corpus", ""))
    threat_class = report.get("threat_class") or _infer_threat_class(corpus)
    check_class = _check_threat_class(entry)
    ees = report.get("ees")
    ees_f = float(ees) if isinstance(ees, (int, float)) else None

    if threat_class != check_class:
        return ProofResolution(
            False,
            f"gate unproven (corpus mismatch): proof covers {threat_class!r}, check is {check_class!r}",
            corpus=corpus,
            threat_class=threat_class,
            ees=ees_f,
        )

    verdicts = report.get("verdicts", {})
    enforced = int(verdicts.get("enforced", 0)) if isinstance(verdicts, dict) else 0
    advised = int(verdicts.get("advised", 0)) if isinstance(verdicts, dict) else 0
    if enforced <= 0 or advised > 0:
        return ProofResolution(
            False,
            f"gate unproven: config does not enforce (enforced={enforced}, advised={advised})",
            corpus=corpus,
            threat_class=threat_class,
            ees=ees_f,
        )

    # Optional strong binding: config sha declared by HB and matching the check.
    declared_sha = report.get("config_sha256")
    strong = bool(
        declared_sha and entry.check.config_ref and declared_sha == entry.check.config_ref
    )
    binding_note = (
        "config-sha bound"
        if strong
        else "name-bound (HB config_sha256 not declared; see CONTRACT-DELTA)"
    )
    return ProofResolution(
        True,
        f"enforced_proof resolved: corpus {corpus!r} covers {check_class!r}, ees={ees_f}, {binding_note}",
        corpus=corpus,
        threat_class=threat_class,
        ees=ees_f,
        strong_binding=strong,
    )
