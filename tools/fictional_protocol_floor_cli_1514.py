"""Strict opt-in local stdin-only fictional version-floor review (#1514).

Canonical RFC JSON bytes only; output is fixed and never grants anything.
exit 2 = fictional REVIEW_ONLY; exit 3 = generic HOLD; never exit 0.
"""
from __future__ import annotations

import json
import sys

from fictional_protocol_floor_review_1514 import (
    FictionalFrame,
    review_protocol_floor,
)

MAX_INPUT_BYTES = 4096


def _no_constants(value: str) -> None:
    raise ValueError("non-RFC numeric literal")


def _no_duplicate_keys(items: list[tuple[str, object]]) -> dict[str, object]:
    record: dict[str, object] = {}
    for key, value in items:
        if key in record:
            raise ValueError("duplicate key")
        record[key] = value
    return record


def _review_raw(raw: bytes) -> str:
    if not raw or len(raw) > MAX_INPUT_BYTES:
        return "HOLD"
    try:
        source = raw.decode("ascii")
        obj = json.loads(
            source,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_no_constants,
        )
        if type(obj) is not dict or list(obj) != [
            "expected_version", "minimum_version", "frames"
        ]:
            return "HOLD"
        if type(obj["frames"]) is not list:
            return "HOLD"
        frames = []
        for item in obj["frames"]:
            if type(item) is not dict or list(item) != [
                "version", "case_id", "sequence"
            ]:
                return "HOLD"
            frames.append(FictionalFrame(item["version"], item["case_id"], item["sequence"]))
        # Reject whitespace, escapes, aliases, exponent/digit spellings, unexpected ordering
        # and all other noncanonical textual encodings; only exact ASCII JSON is admitted.
        canonical = json.dumps(
            obj, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
        if source != canonical:
            return "HOLD"
        return review_protocol_floor(
            tuple(frames), obj["expected_version"], obj["minimum_version"]
        ).status
    except (ValueError, UnicodeError, TypeError, OverflowError, KeyError, RecursionError):
        return "HOLD"


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        status = _review_raw(raw)
    except (OSError, ValueError):
        status = "HOLD"
    sys.stdout.write(status + "\n")
    return 2 if status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
