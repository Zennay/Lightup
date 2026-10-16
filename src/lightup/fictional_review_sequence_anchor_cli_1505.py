"""Opt-in canonical offline anchor-vs-segments review #1505.

All records are wholly fictional caller-controlled copies, NEVER trusted
provenance, client/operator consent, an activation grant or release approval.
Return REVIEW_ONLY via exit 2 or generic HOLD via exit 3; never exit 0.
"""
from __future__ import annotations

import json
import sys

from lightup.fictional_review_sequence_1505 import FictionalHandoff, ReviewOutcome
from lightup.fictional_review_sequence_anchor_1505 import (
    review_fictional_segments_against_capture,
)
from lightup.fictional_review_sequence_cli_1505 import (
    _invalid_constant, _read_bounded_to_eof, _unique_pairs, emit_review,
)
from lightup.fictional_review_sequence_segments_cli_1505 import (
    parse_fictional_segments,
)

_TOP = ("schema", "expected_records", "segments", "capture")
_ROWS = ("records",)
_RECORD = ("case_id", "sequence", "packet_sha256", "observed_at")
_MAX_BYTES = 8192


def parse_fictional_anchor(payload: bytes) -> ReviewOutcome:
    hold = ReviewOutcome("HOLD")
    if type(payload) is not bytes or not 1 <= len(payload) <= _MAX_BYTES or not payload.isascii():
        return hold
    try:
        data = json.loads(payload.decode("ascii"), object_pairs_hook=_unique_pairs,
                          parse_constant=_invalid_constant)
        if type(data) is not dict or tuple(data) != _TOP:
            return hold
        if (type(data["schema"]) is not str or
                data["schema"] != "fictional_handoff_anchor_v1"):
            return hold
        expected = data["expected_records"]
        if type(expected) is not int or not 2 <= expected <= 16:
            return hold
        segments = data["segments"]
        capture = data["capture"]
        if type(segments) is not list or not 2 <= len(segments) <= 4:
            return hold
        if type(capture) is not dict or tuple(capture) != _ROWS:
            return hold
        complete = capture["records"]
        if type(complete) is not list or len(complete) != expected:
            return hold
        if any(type(row) is not dict or tuple(row) != _RECORD for row in complete):
            return hold
        if (any(type(s) is not dict or tuple(s) != _ROWS or
                type(s["records"]) is not list or not 1 <= len(s["records"]) <= 16 or
                any(type(r) is not dict or tuple(r) != _RECORD for r in s["records"])
                for s in segments)):
            return hold

        # Canonical serialization and unique-pairs hook reject aliases,
        # reordered fields, duplicate keys, JSON escapes and trailing bytes.
        canonical = json.dumps(data, separators=(",", ":"), ensure_ascii=True,
                               allow_nan=False).encode("ascii")
        if payload != canonical:
            return hold
        # First validate the isolated segmented envelope as originally defined.
        envelope = {
            "schema": "fictional_handoff_segments_v1",
            "expected_records": expected,
            "segments": segments,
        }
        segment_bytes = json.dumps(envelope, separators=(",", ":"), ensure_ascii=True,
                                   allow_nan=False).encode("ascii")
        if parse_fictional_segments(segment_bytes).status != "REVIEW_ONLY":
            return hold
        fragments = tuple(tuple(FictionalHandoff(*(r[k] for k in _RECORD))
                                for r in s["records"]) for s in segments)
        baseline = tuple(FictionalHandoff(*(r[k] for k in _RECORD))
                         for r in complete)
        return review_fictional_segments_against_capture(fragments, expected, baseline)
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError, KeyError):
        return hold


def main() -> int:
    result = ReviewOutcome("HOLD")
    if len(sys.argv) == 1:
        try:
            result = parse_fictional_anchor(_read_bounded_to_eof(sys.stdin.buffer))
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
