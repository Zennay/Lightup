"""Standalone strict decoder reference for historical finding evidence JSON.

Opt-in pure helper only; NOT connected to DomainStore._finding_from_row,
the web application, retest, Security Twin, or any authorization decision.
Original finding-read source owners retain canonical integration authority.
"""
from __future__ import annotations

import json

_MAX_JSON_BYTES = 262_144
_MAX_REFERENCES = 128
_MAX_REFERENCE_BYTES = 4096
_ERROR = "invalid persisted finding evidence integrity"


def _invalid_constant(_value: str) -> None:
    raise ValueError(_ERROR)


def decode_finding_evidence_checked(raw: object) -> tuple[str, ...]:
    """Return exact ordered evidence references or one deterministic ValueError.

    An empty list remains valid for historic manual findings. The function
    does not attempt to repair, trim, coerce, authenticate or persist records.
    The size ceilings are *provisional* for source-owner compatibility review.
    """
    if type(raw) is not str:
        raise ValueError(_ERROR)
    try:
        if len(raw.encode("utf-8", "strict")) > _MAX_JSON_BYTES:
            raise ValueError(_ERROR)
        parsed = json.loads(raw, parse_constant=_invalid_constant)
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError) as exc:
        raise ValueError(_ERROR) from exc

    if type(parsed) is not list or len(parsed) > _MAX_REFERENCES:
        raise ValueError(_ERROR)

    observed: set[str] = set()
    checked: list[str] = []
    for reference in parsed:
        if type(reference) is not str or not reference.strip():
            raise ValueError(_ERROR)
        try:
            if len(reference.encode("utf-8", "strict")) > _MAX_REFERENCE_BYTES:
                raise ValueError(_ERROR)
        except UnicodeError as exc:
            raise ValueError(_ERROR) from exc
        if reference in observed:
            raise ValueError(_ERROR)
        observed.add(reference)
        checked.append(reference)

    return tuple(checked)
