#!/usr/bin/env python3
"""Read-only exact immutable original-source reopening of PRIVATE HUMAN review notes."""
from __future__ import annotations

import argparse
import csv
import os
import stat
import sys

from curate import Hold
from packet_open import read_private
from priority_inbox import ensure_output_outside_inputs
from priority_inbox_continuity_docket import FILTERS, LIMIT, require_outside_aggregate_folder
from priority_inbox_continuity_review import build


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: PRIVATE source-bound HUMAN review-return output changed")


def reopen(source: str, manifest: str, worksheet: str, selection_receipt: str,
           selection: str, curated: str, handoffs: list[str],
           replies: list[list[str]], inboxes: list[str], filter_mode: str,
           ordinals: list[int], original_docket: str, human_return_csv: str,
           saved_review: str) -> int:
    require_outside_aggregate_folder(saved_review)
    ensure_output_outside_inputs(
        saved_review, [curated, *handoffs, *inboxes, original_docket])
    expected, count = build(
        source, manifest, worksheet, selection_receipt,
        selection, curated, handoffs, replies, inboxes, filter_mode,
        ordinals, original_docket, human_return_csv)
    require(all(0 < len(raw) <= LIMIT for raw in expected.values()))
    fd = -1
    try:
        fd = os.open(saved_review, os.O_RDONLY |
                     getattr(os, "O_DIRECTORY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        stats = os.fstat(fd)
        require(stat.S_ISDIR(stats.st_mode) and
                stats.st_uid == os.getuid() and
                stat.S_IMODE(stats.st_mode) == 0o700 and
                set(os.listdir(fd)) == set(expected))
        for name, original in expected.items():
            require(read_private(fd, name, max(1, len(original))) == original)
        return count
    finally:
        if fd >= 0:
            os.close(fd)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Read-only original-source/private-HUMAN-reply exact review-return reopen")
    for name in ("source", "manifest", "worksheet", "selection-receipt",
                 "selection", "curated-packet", "private-docket-dir",
                 "review-returned-csv", "private-review-dir"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--private-handoff", action="append", required=True)
    p.add_argument("--round-inbox", action="append", required=True)
    p.add_argument("--round-returned-csv", action="append", required=True)
    p.add_argument("--filter", choices=FILTERS, default="attention")
    p.add_argument("--human-ordinal", action="append", type=int)
    a = p.parse_args()
    try:
        rounds, groups = len(a.round_inbox), len(a.private_handoff)
        require(2 <= rounds <= 8 and 1 <= groups <= 3 and
                len(a.round_returned_csv) == rounds * groups)
        replies = [a.round_returned_csv[i:i+groups]
                   for i in range(0, rounds * groups, groups)]
        count = reopen(
            a.source, a.manifest, a.worksheet, a.selection_receipt,
            a.selection, a.curated_packet, a.private_handoff, replies,
            a.round_inbox, a.filter, a.human_ordinal or [],
            a.private_docket_dir, a.review_returned_csv, a.private_review_dir)
    except (Hold, OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, MemoryError, RecursionError, csv.Error):
        print("HOLD: saved PRIVATE HUMAN review return differs from original bytes",
              file=sys.stderr)
        return 3
    print("PRIVATE original-source HUMAN reviewer notes reopened for " +
          str(count) + " original selected rows; no identity or approval inferred.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
