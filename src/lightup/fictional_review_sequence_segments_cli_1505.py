"""Opt-in, bounded stdin transport for wholly fictional 2..4 segment review.

REVIEW_ONLY exit2 is NOT authority. Generic HOLD exit3; never success exit0.
No integration to scope, grants, runtime dispatch, clients or deployments.
"""
from __future__ import annotations

import json
import sys

from lightup.fictional_review_sequence_1505 import FictionalHandoff, ReviewOutcome
from lightup.fictional_review_sequence_segments_1505 import review_fictional_segment_join
from lightup.fictional_review_sequence_cli_1505 import (
    _invalid_constant, _read_bounded_to_eof, _unique_pairs, emit_review,
)

_FIELDS = ("schema", "expected_records", "segments")
_SEGMENT = ("records",)
_RECORD = ("case_id", "sequence", "packet_sha256", "observed_at")


def parse_fictional_segments(payload: bytes) -> ReviewOutcome:
    hold = ReviewOutcome("HOLD")
    if type(payload) is not bytes or not 1 <= len(payload) <= 8192 or not payload.isascii():
        return hold
    try:
        data = json.loads(payload.decode("ascii"), object_pairs_hook=_unique_pairs,
                          parse_constant=_invalid_constant)
        if type(data) is not dict or tuple(data) != _FIELDS:
            return hold
        if type(data["schema"]) is not str or data["schema"] != "fictional_handoff_segments_v1":
            return hold
        total = data["expected_records"]
        if type(total) is not int or not 2 <= total <= 16:
            return hold
        chunks = data["segments"]
        if type(chunks) is not list or not 2 <= len(chunks) <= 4:
            return hold
        segments = []
        count = 0
        for chunk in chunks:
            if type(chunk) is not dict or tuple(chunk) != _SEGMENT:
                return hold
            records = chunk["records"]
            if type(records) is not list or not 1 <= len(records) <= 16:
                return hold
            count += len(records)
            if count > 16:
                return hold
            if any(type(row) is not dict or tuple(row) != _RECORD for row in records):
                return hold
            segments.append(tuple(FictionalHandoff(*(row[k] for k in _RECORD)) for row in records))
        canonical = json.dumps(data, separators=(",", ":"), ensure_ascii=True,
                               allow_nan=False).encode("ascii")
        if canonical != payload:
            return hold
        return review_fictional_segment_join(tuple(segments), total)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError, UnicodeError):
        return hold


def main() -> int:
    result = ReviewOutcome("HOLD")
    if len(sys.argv) == 1:
        try:
            result = parse_fictional_segments(_read_bounded_to_eof(sys.stdin.buffer))
        except (OSError, ValueError, TypeError, AttributeError):
            result = ReviewOutcome("HOLD")
    try:
        sys.stdout.write(emit_review(result) + "\n")
        sys.stdout.flush()
    except (OSError, UnicodeError, ValueError, TypeError):
        return 3
    return 2 if result.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
