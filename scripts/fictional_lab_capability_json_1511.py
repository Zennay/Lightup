"""Shared canonical, bounded, offline JSON decoder for #1511 review CLIs.

Pure parsing only: never authenticate sources, verify actual grants, or
permit target execution. A successfully parsed envelope is still untrusted.
"""
from __future__ import annotations

import json

_MAX_BYTES = 4096
_KEYS = ("schema", "requested", "allowlist")


class _RejectJSON(ValueError):
    """Internal sentinel; callers always emit generic HOLD, never details."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _RejectJSON("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonstandard_numeric(value: str) -> object:
    # JSON RFC 8259 does not have NaN or Infinity (Python normally accepts them).
    raise _RejectJSON("nonstandard JSON number")


def parse_fictional_envelope_1511(
    data: object, *, expected_schema: str, requested_type: type
) -> dict[str, object] | None:
    """Return canonical envelope or None; *never* authority.

    Accept exactly 1..4096 ASCII bytes with fixed ordered keys,
    no duplicates, no non-JSON numeric constants, no unknown fields,
    no escape variants, no whitespace/trailing data, and exact field types.
    """
    if type(data) is not bytes or not 1 <= len(data) <= _MAX_BYTES:
        return None
    if type(expected_schema) is not str or requested_type not in (str, list):
        return None
    try:
        raw = data.decode("ascii")
        decoded = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_numeric,
        )
        if type(decoded) is not dict or tuple(decoded) != _KEYS:
            return None
        if type(decoded["schema"]) is not str or decoded["schema"] != expected_schema:
            return None
        if type(decoded["requested"]) is not requested_type:
            return None
        if type(decoded["allowlist"]) is not list:
            return None
        # No Python special float extensions, no alternate spellings,
        # no Unicode escaping, no normalized key order, and no aliases.
        if json.dumps(
            decoded, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        ) != raw:
            return None
        return decoded
    except (ValueError, UnicodeError, TypeError, KeyError, OverflowError, RecursionError):
        return None
