#!/usr/bin/env python3
"""Read-only exact original-source reopen of a PRIVATE aggregate HUMAN portfolio."""
from __future__ import annotations

import argparse
import csv
import os
import stat
import sys

from curate import Hold
from packet_open import read_private
from priority_inbox import ensure_output_outside_inputs
from priority_inbox_portfolio import LIMIT, build


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: original HUMAN portfolio source/custody mismatch")


def reopen(source: str, manifest: str, worksheet: str, selection_receipt: str,
           selection: str, curated: str, handoffs: list[str],
           round_replies: list[list[str]], round_inboxes: list[str],
           saved_dir: str) -> int:
    ensure_output_outside_inputs(saved_dir, [curated, *handoffs, *round_inboxes])
    expected, count = build(source, manifest, worksheet, selection_receipt,
                            selection, curated, handoffs, round_replies, round_inboxes)
    require(all(0 < len(raw) <= LIMIT for raw in expected.values()))
    fd = -1
    try:
        fd = os.open(saved_dir, os.O_RDONLY |
                     getattr(os, "O_DIRECTORY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o700 and
                set(os.listdir(fd)) == set(expected))
        for filename, expected_raw in expected.items():
            require(read_private(fd, filename, max(1, len(expected_raw))) ==
                    expected_raw)
        return count
    finally:
        if fd >= 0:
            os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only exact original-source PRIVATE HUMAN portfolio reopen")
    for key in ("source", "manifest", "worksheet", "selection-receipt",
                "selection", "curated-packet", "private-portfolio-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--round-inbox", action="append", required=True)
    parser.add_argument("--round-returned-csv", action="append", required=True)
    args = parser.parse_args()
    try:
        rounds = len(args.round_inbox)
        per_round = len(args.private_handoff)
        require(2 <= rounds <= 8 and 1 <= per_round <= 3 and
                len(args.round_returned_csv) == rounds * per_round)
        reply_groups = [args.round_returned_csv[i:i + per_round]
                        for i in range(0, len(args.round_returned_csv), per_round)]
        count = reopen(args.source, args.manifest, args.worksheet,
                       args.selection_receipt, args.selection,
                       args.curated_packet, args.private_handoff,
                       reply_groups, args.round_inbox, args.private_portfolio_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError, csv.Error):
        print("HOLD: saved PRIVATE portfolio or original source/round bytes drifted; "
              "nothing changed", file=sys.stderr)
        return 3
    print("PRIVATE aggregate HUMAN portfolio reopened against original sources and " +
          str(count) + " original selected rows; REVIEW_ONLY, unsigned.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
