"""Read-only, opt-in two-capture fictional history comparer (#1505).

Two matching untrusted copies do NOT authenticate provenance, consent or release.
Exit 2 is REVIEW_ONLY and never approval; all other outcomes exit 3 (HOLD).
"""
from __future__ import annotations

import json
import sys

from lightup.fictional_review_sequence_1505 import FictionalHandoff, ReviewOutcome
from lightup.fictional_review_sequence_compare_1505 import review_matching_fictional_captures
from lightup.fictional_review_sequence_cli_1505 import (
    _read_bounded_to_eof, _unique_pairs, _invalid_constant, parse_fictional_stdin, emit_review,
)

_SCHEMA = "fictional_handoff_pair_v1"
_FIELDS = ("schema", "capture_a", "capture_b")
_RECORD_FIELDS = ("case_id", "sequence", "packet_sha256", "observed_at")


def parse_fictional_pair(payload: bytes) -> ReviewOutcome:
    hold = ReviewOutcome("HOLD")
    if type(payload) is not bytes or not 1 <= len(payload) <= 8192 or not payload.isascii():
        return hold
    try:
        data = json.loads(payload.decode("ascii"), object_pairs_hook=_unique_pairs,
                          parse_constant=_invalid_constant)
        if type(data) is not dict or tuple(data) != _FIELDS:
            return hold
        if type(data["schema"]) is not str or data["schema"] != _SCHEMA:
            return hold
        canonical = json.dumps(data, separators=(",", ":"), ensure_ascii=True,
                               allow_nan=False).encode("ascii")
        if payload != canonical:
            return hold
        captures = []
        for key in ("capture_a", "capture_b"):
            entry = data[key]
            if type(entry) is not dict:
                return hold
            candidate = json.dumps(entry, separators=(",", ":"), ensure_ascii=True,
                                   allow_nan=False).encode("ascii")
            if parse_fictional_stdin(candidate).status != "REVIEW_ONLY":
                return hold
            captures.append(tuple(
                FictionalHandoff(*(item[k] for k in _RECORD_FIELDS))
                for item in entry["records"]
            ))
        return review_matching_fictional_captures(captures[0], captures[1])
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError, KeyError):
        return hold


def main() -> int:
    result = ReviewOutcome("HOLD")
    if len(sys.argv) == 1:
        try:
            result = parse_fictional_pair(_read_bounded_to_eof(sys.stdin.buffer))
        except (OSError, ValueError, TypeError):
            result = ReviewOutcome("HOLD")
    try:
        sys.stdout.write(emit_review(result) + "\n")
        sys.stdout.flush()
    except (OSError, UnicodeError):
        return 3
    return 2 if result.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
