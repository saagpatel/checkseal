"""Strict JSON decoding for signed CheckSeal statements."""

from __future__ import annotations

import json
from typing import Any

from .model import VCRError


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VCRError("duplicate JSON object member")
        result[key] = value
    return result


def loads_unique_json(raw: str | bytes) -> Any:
    """Parse JSON while rejecting object member names that occur more than once."""
    return json.loads(raw, object_pairs_hook=_unique_object)
