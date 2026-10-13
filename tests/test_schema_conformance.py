from __future__ import annotations

import json
from pathlib import Path

import pytest

from checkseal.model import Runtime, VCRError
from checkseal.statement import parse_statement

FIXTURES = Path(__file__).parent / "fixtures" / "schema"


def test_shared_valid_statement_parses_and_preserves_unknown_subject_kind():
    statement = json.loads((FIXTURES / "valid-statement.json").read_text())
    predicate = parse_statement(statement)
    assert predicate.subject.kind == "future-kind"
    assert predicate.vcr_version == "0.2"


def test_shared_invalid_statement_is_rejected():
    statement = json.loads((FIXTURES / "invalid-statement.json").read_text())
    with pytest.raises(VCRError, match="vcr_version"):
        parse_statement(statement)


def test_runtime_rejects_negative_duration():
    with pytest.raises(VCRError, match="duration_ms"):
        Runtime.from_jsonable({"ran_at": "now", "runner": "ci", "duration_ms": -1})
