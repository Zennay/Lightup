"""Opt-in bounded fictional predecessor hint review CLI (#1505).

Canonical ASCII JSON only. REVIEW_ONLY exit 2 is not approval or provenance.
Generic no-echo HOLD exit 3. Never exits 0 or dispatches handlers.
"""
from __future__ import annotations

import json
import sys

from lightup.fictional_review_sequence_1505 import ReviewOutcome
from lightup.fictional_review_sequence_cli_1505 import (
    _invalid_constant, _read_bounded_to_eof, _unique_pairs, emit_review,
)
from lightup.fictional_review_sequence_linked_1505 import (
    FictionalLinkedHandoff, review_fictional_parent_links,
)

_SCHEMA = "fictional_handoff_links_v1"
_ENVELOPE = ("schema", "records")
_RECORD = ("case_id", "sequence", "packet_sha256", "observed_at", "previous_packet_sha256")


def parse_fictional_links(payload: bytes) -> ReviewOutcome:
    hold = ReviewOutcome("HOLD")
    if type(payload) is not bytes or not 1 <= len(payload) <= 8192 or not payload.isascii():
        return hold
    try:
        data = json.loads(payload.decode("ascii"), object_pairs_hook=_unique_pairs,
                          parse_constant=_invalid_constant)
        if type(data) is not dict or tuple(data) != _ENVELOPE:
            return hold
        if type(data["schema"]) is not str or data["schema"] != _SCHEMA:
            return hold
        rows = data["records"]
        if type(rows) is not list or not 2 <= len(rows) <= 16:
            return hold
        if any(type(row) is not dict or tuple(row) != _RECORD for row in rows):
            return hold
        if json.dumps(data, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii") != payload:
            return hold
        return review_fictional_parent_links(tuple(FictionalLinkedHandoff(
            *(row[key] for key in _RECORD)) for row in rows))
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError, KeyError):
        return hold


def main() -> int:
    result = ReviewOutcome("HOLD")
    if len(sys.argv) == 1:
        try:
            result = parse_fictional_links(_read_bounded_to_eof(sys.stdin.buffer))
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
