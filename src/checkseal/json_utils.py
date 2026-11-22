"""Strict JSON decoding for signed CheckSeal statements and envelopes.

The JavaScript verifier (js/checkseal_verify.mjs) applies the same rules, so both
clients accept exactly the same JSON texts:

* object member names occur at most once (compared after unescaping);
* nesting depth of arrays and objects is at most ``MAX_JSON_DEPTH``;
* the non-standard constants ``NaN``, ``Infinity`` and ``-Infinity`` are refused;
* every number must be finite as an IEEE-754 double (JavaScript reads larger
  literals as Infinity), so ``1e400`` or a 400-digit integer is refused.
"""

from __future__ import annotations

import json
import math
from typing import Any, NoReturn

from .model import VCRError

MAX_JSON_DEPTH = 64

# A JSON integer literal with this many digits (no leading zeros) is >= 10**309,
# which is beyond the largest finite double.
_MAX_FINITE_INT_DIGITS = 309


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VCRError("duplicate JSON object member")
        result[key] = value
    return result


def _refuse_constant(name: str) -> NoReturn:
    raise VCRError(f"non-standard JSON constant {name} is not allowed")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise VCRError("JSON number is not a finite double")
    return value


def _finite_int(text: str) -> int:
    if len(text.lstrip("-")) > _MAX_FINITE_INT_DIGITS:
        raise VCRError("JSON number is not a finite double")
    value = int(text)
    try:
        float(value)
    except OverflowError as exc:
        raise VCRError("JSON number is not a finite double") from exc
    return value


def json_depth_ok(text: str, limit: int = MAX_JSON_DEPTH) -> bool:
    """True when arrays and objects nest at most ``limit`` deep (strings skipped)."""
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c in "[{":
            depth += 1
            if depth > limit:
                return False
        elif c in "]}":
            depth -= 1
        i += 1
    return True


def loads_unique_json(raw: str | bytes) -> Any:
    """Parse JSON under the strict rules above; raise VCRError on any violation."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VCRError(f"JSON text is not valid UTF-8 ({exc})") from exc
    if not json_depth_ok(raw):
        raise VCRError(f"JSON nesting deeper than {MAX_JSON_DEPTH} is not allowed")
    return json.loads(
        raw,
        object_pairs_hook=_unique_object,
        parse_constant=_refuse_constant,
        parse_float=_finite_float,
        parse_int=_finite_int,
    )
