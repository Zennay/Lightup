"""Explicit opt-in offline stdin transport for fictional sequence review #1505.

This is NOT linked to a web endpoint, runtime scope policy or authorization.
Exit 2 = REVIEW_ONLY (not consent), 3 = generic HOLD; NEVER exit 0.
"""
from __future__ import annotations

import json
import sys

from lightup.fictional_review_sequence_1505 import (
    FictionalHandoff, ReviewOutcome, review_fictional_handoff_sequence,
)

_MAX_BYTES = 8192
_KEYS = ("case_id", "sequence", "packet_sha256", "observed_at")
_ENVELOPE = ("schema", "records")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    data: dict[str, object] = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate key")
        data[key] = value
    return data


def _invalid_constant(_value: str) -> object:
    raise ValueError("noncanonical constant")


def parse_fictional_stdin(payload: bytes) -> ReviewOutcome:
    """Canonical tiny ASCII JSON only, no parsing ambiguity or data echo."""
    hold = ReviewOutcome("HOLD")
    if type(payload) is not bytes or not 1 <= len(payload) <= _MAX_BYTES or not payload.isascii():
        return hold
    try:
        text = payload.decode("ascii")
        obj = json.loads(text, object_pairs_hook=_unique_pairs,
                         parse_constant=_invalid_constant)
        if type(obj) is not dict or tuple(obj) != _ENVELOPE:
            return hold
        if obj["schema"] != "fictional_handoff_sequence_v1" or type(obj["schema"]) is not str:
            return hold
        items = obj["records"]
        if type(items) is not list or not 2 <= len(items) <= 16:
            return hold
        if any(type(item) is not dict or tuple(item) != _KEYS for item in items):
            return hold
        canonical = json.dumps(obj, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        if canonical != payload:
            return hold
        records = tuple(FictionalHandoff(*(item[k] for k in _KEYS)) for item in items)
        return review_fictional_handoff_sequence(records)
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        return hold


def emit_review(result: ReviewOutcome) -> str:
    """Return bounded fixed-schema output, never caller payload values."""
    if (type(result) is not ReviewOutcome
            or type(result.status) is not str
            or type(result.checked_records) is not int
            or result.status not in ("HOLD", "REVIEW_ONLY")
            or (result.status == "HOLD" and result.checked_records != 0)
            or (result.status == "REVIEW_ONLY" and not 2 <= result.checked_records <= 16)
            or any(type(getattr(result, f)) is not bool or getattr(result, f) is not False for f in
                   ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"))):
        result = ReviewOutcome("HOLD")
    return json.dumps({
        "schema": "fictional_handoff_review_v1",
        "status": result.status,
        "checked_records": result.checked_records,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }, separators=(",", ":"), ensure_ascii=True)


def _read_bounded_to_eof(reader: object) -> bytes:
    """Read an entire finite fictional envelope, not just one fragmented read.

    Even an exactly 8192-byte payload needs a final one-byte EOF check.  Never
    request more than the remaining cap+1 and stop without further reads once
    an overlong or non-builtin bytes chunk is observed.
    """
    fragments: list[bytes] = []
    total = 0
    while True:
        allowance = _MAX_BYTES + 1 - total
        if allowance <= 0:
            raise ValueError("oversized fictional input")
        chunk = reader.read(allowance)
        if type(chunk) is not bytes or len(chunk) > allowance:
            raise ValueError("noncanonical stdin chunk")
        if not chunk:
            return b"".join(fragments)
        total += len(chunk)
        if total > _MAX_BYTES:
            raise ValueError("oversized fictional input")
        fragments.append(chunk)


def main() -> int:
    result = ReviewOutcome("HOLD")
    if len(sys.argv) == 1:
        try:
            result = parse_fictional_stdin(_read_bounded_to_eof(sys.stdin.buffer))
        except (OSError, ValueError, TypeError, AttributeError):
            result = ReviewOutcome("HOLD")
    rendered = emit_review(result)
    try:
        sys.stdout.write(rendered + "\n")
        sys.stdout.flush()
    except (OSError, UnicodeError, ValueError, TypeError):
        return 3
    return 2 if result.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
