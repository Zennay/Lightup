#!/usr/bin/env python3
"""Read-only offline review-history consistency: every transition must narrow.

Syntactic review history is untrusted; not verified authorization or execution.
"""
from __future__ import annotations

import argparse
import json
import sys

import check_scope_review_batch_offline as batch
import check_scope_review_delta_offline as delta
import check_scope_review_packet_offline as single

MIN_VERSIONS = 2
MAX_VERSIONS = 4
MAX_TOTAL_BYTES = 128 * 1024


class HistoryHold(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def compare_history(raw_versions: object) -> dict[str, object]:
    """Reject transient widening even when the final snapshot narrows again."""
    state, reason, transitions, narrowed = "HOLD", "INVALID_HISTORY", 0, 0
    try:
        if type(raw_versions) is not tuple or not MIN_VERSIONS <= len(raw_versions) <= MAX_VERSIONS:
            raise HistoryHold("VERSION_COUNT")
        if any(type(raw) is not bytes for raw in raw_versions):
            raise HistoryHold("INVALID_FILE_BYTES")
        if (any(len(raw) > batch.MAX_BATCH_BYTES for raw in raw_versions)
                or sum(len(raw) for raw in raw_versions) > MAX_TOTAL_BYTES):
            raise HistoryHold("SIZE_LIMIT")
        # Only count after the entire chain has passed. All receipts remain
        # fixed, private, unverified and non-authorizing, even for success.
        for previous, proposed in zip(raw_versions, raw_versions[1:]):
            result = delta.compare(previous, proposed)
            if result["state"] != "REVIEW_ONLY":
                raise HistoryHold(result["reason"])
            transitions += 1
            narrowed += result["narrowed_requests"] + result["removed_requests"]
        state, reason = "REVIEW_ONLY", "SYNTAX_ONLY_UNVERIFIED"
    except HistoryHold as exc:
        state, reason, transitions, narrowed = "HOLD", exc.code, 0, 0
    return {
        "state": state, "reason": reason, "transitions_checked": transitions,
        "narrowing_events": narrowed, "non_authorizing": True,
        **single.AUTHORITY_FLAGS,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version_files", nargs="+",
                        help="2–4 local JSON batch versions in oldest-to-newest order")
    parser.add_argument("--require-private-file", action="store_true",
                        help="Enforce POSIX owner-only private-file checks on every version")
    args = parser.parse_args(argv)
    if not MIN_VERSIONS <= len(args.version_files) <= MAX_VERSIONS:
        receipt = compare_history(tuple())
    else:
        try:
            versions = tuple(
                batch.read_batch_file(path, require_private_file=args.require_private_file)
                for path in args.version_files
            )
            receipt = compare_history(versions)
        except batch.BatchHold as exc:
            receipt = {
                "state": "HOLD", "reason": exc.code,
                "transitions_checked": 0, "narrowing_events": 0,
                "non_authorizing": True, **single.AUTHORITY_FLAGS,
            }
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["state"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
