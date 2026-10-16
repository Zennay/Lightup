"""Read-only opt-in stdin consistency of wholly fictional chain terminal pin.

All hints are untrusted caller strings. Nonzero exit 2 = REVIEW_ONLY and
exit 3 = HOLD. No success exit 0, grant, scan, dispatch or authorization.
"""
from __future__ import annotations

import json
import sys

from lightup.fictional_review_sequence_1505 import ReviewOutcome
from lightup.fictional_review_sequence_linked_1505 import FictionalLinkedHandoff
from lightup.fictional_review_sequence_tip_1505 import review_fictional_tip_pin
from lightup.fictional_review_sequence_cli_1505 import (
    _invalid_constant, _read_bounded_to_eof, _unique_pairs, emit_review,
)
from lightup.fictional_review_sequence_linked_cli_1505 import parse_fictional_links

_TOP = ("schema", "expected_tip_sha256", "records")
_ROW = ("case_id", "sequence", "packet_sha256", "observed_at", "previous_packet_sha256")
_VERSION = "fictional_handoff_tip_v1"


def parse_fictional_tip(payload: bytes) -> ReviewOutcome:
    hold = ReviewOutcome("HOLD")
    if type(payload) is not bytes or not 1 <= len(payload) <= 8192 or not payload.isascii():
        return hold
    try:
        obj = json.loads(payload.decode("ascii"), object_pairs_hook=_unique_pairs,
                         parse_constant=_invalid_constant)
        if type(obj) is not dict or tuple(obj) != _TOP:
            return hold
        if type(obj["schema"]) is not str or obj["schema"] != _VERSION:
            return hold
        if type(obj["expected_tip_sha256"]) is not str:
            return hold
        records = obj["records"]
        if type(records) is not list or not 2 <= len(records) <= 16:
            return hold
        if any(type(row) is not dict or tuple(row) != _ROW for row in records):
            return hold
        canonical = json.dumps(obj, separators=(",", ":"), ensure_ascii=True,
                               allow_nan=False).encode("ascii")
        if canonical != payload:
            return hold
        envelope = json.dumps(
            {"schema": "fictional_handoff_links_v1", "records": records},
            separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        if parse_fictional_links(envelope).status != "REVIEW_ONLY":
            return hold
        return review_fictional_tip_pin(tuple(
            FictionalLinkedHandoff(*(row[key] for key in _ROW)) for row in records
        ), obj["expected_tip_sha256"])
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError, KeyError):
        return hold


def main() -> int:
    result = ReviewOutcome("HOLD")
    if len(sys.argv) == 1:
        try:
            result = parse_fictional_tip(_read_bounded_to_eof(sys.stdin.buffer))
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
