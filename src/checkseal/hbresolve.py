"""Resolve an ``enforced_proof`` against a HarnessBench report.

Verifier Contract step 4, with the N1 CONTRACT-DELTA: it is not enough that the
HarnessBench record exists and covers check.id@config_ref. The corpus's threat
class must match the check's semantic class, or the proof is rendered "gate
unproven (corpus mismatch)". A destructive-execution corpus does NOT prove a
content rights-gate; treating it as if it did is exactly the over-claim
CheckSeal exists to prevent.

The corpus/class match is defense-in-depth only: ``check.id`` (and the class
derived from it) is producer-controlled, so a name match is forgeable. The
security boundary is a cryptographic one: resolution requires the HarnessBench
report to declare a ``config_sha256`` equal to the seal's ``check.config_ref``,
so the producer must exhibit a report that measured THIS exact config. Two asks
of HarnessBench (N2) make that possible (see DESIGN.md CONTRACT-DELTA):
  (a) declare ``threat_class`` on each report;
  (b) declare the subject config's ``config_sha256`` on each report.
Until HB ships (b), NOTHING resolves, and the verifier renders "gate unproven
(weak binding)" rather than trusting a forgeable name match.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .digest import sha256_hex
from .model import CheckEntry, EnforcedProof

# Enforcement-efficacy floor: an enforced verdict below this EES is not a proof.
EES_FLOOR = 0.5

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
        return ProofResolution(False, f"gate unproven: not a HarnessBench report (schema={schema!r})")

    corpus = str(report.get("corpus", ""))
    threat_class = report.get("threat_class") or _infer_threat_class(corpus)
    check_class = _check_threat_class(entry)
    ees = report.get("ees")
    ees_f = float(ees) if isinstance(ees, (int, float)) and not isinstance(ees, bool) else None

    # Necessary (not sufficient): the corpus threat class must cover the check.
    # NOTE: check_class is derived from the producer-controlled check.id, so this
    # match is forgeable on its own. It is defense-in-depth, not the boundary.
    if threat_class != check_class:
        return ProofResolution(
            False,
            f"gate unproven (corpus mismatch): proof covers {threat_class!r}, check is {check_class!r}",
            corpus=corpus,
            threat_class=threat_class,
            ees=ees_f,
        )

    # The measured config must enforce, not merely advise.
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

    # Enforcement efficacy floor: an enforced verdict on a barely-effective config
    # is not a proof. EES is HarnessBench's headline metric; require it and a floor.
    if ees_f is None or ees_f < EES_FLOOR:
        return ProofResolution(
            False,
            f"gate unproven: enforcement-efficacy score {ees_f} below floor {EES_FLOOR}",
            corpus=corpus,
            threat_class=threat_class,
            ees=ees_f,
        )

    # THE SECURITY BOUNDARY. check.id and the derived threat class are all
    # producer-controlled, so a name/class match is forgeable (rename the check
    # and any corpus "covers" it). The only unforgeable binding is a config_sha256
    # declared by HarnessBench equal to the seal's check.config_ref: to resolve,
    # the producer must exhibit an HB report that measured THIS exact config. Until
    # HB declares config_sha256 (CONTRACT-DELTA ask b), nothing resolves, and the
    # verifier renders "gate unproven" rather than trusting a forgeable name match.
    declared_sha = report.get("config_sha256")
    strong = bool(
        isinstance(declared_sha, str)
        and entry.check.config_ref is not None
        and declared_sha == entry.check.config_ref
    )
    if not strong:
        why = (
            "HB report declares no config_sha256"
            if not isinstance(declared_sha, str)
            else "config_sha256 does not match check.config_ref"
        )
        return ProofResolution(
            False,
            f"gate unproven (weak binding): {why}; resolution requires config_sha256 == "
            "check.config_ref (see CONTRACT-DELTA ask b)",
            corpus=corpus,
            threat_class=threat_class,
            ees=ees_f,
            strong_binding=False,
        )

    return ProofResolution(
        True,
        f"enforced_proof resolved: config_sha256 bound, corpus {corpus!r} covers {check_class!r}, ees={ees_f}",
        corpus=corpus,
        threat_class=threat_class,
        ees=ees_f,
        strong_binding=True,
    )
