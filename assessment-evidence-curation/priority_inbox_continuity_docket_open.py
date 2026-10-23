#!/usr/bin/env python3
"""Read-only exact original-source and owner-custody reopening of HUMAN docket."""
from __future__ import annotations

import argparse
import csv
import os
import stat
import sys

from curate import Hold
from packet_open import read_private
from priority_inbox import ensure_output_outside_inputs
from priority_inbox_continuity_docket import (
    LIMIT, FILTERS, build, require_outside_aggregate_folder,
)


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: PRIVATE HUMAN continuity docket custody/source mismatch")


def reopen(source: str, manifest: str, worksheet: str, selection_receipt: str,
           selection: str, curated: str, handoffs: list[str],
           replies: list[list[str]], inboxes: list[str], filter_mode: str,
           human_ordinals: list[int], private_docket_dir: str) -> int:
    require_outside_aggregate_folder(private_docket_dir)
    ensure_output_outside_inputs(
        private_docket_dir, [curated, *handoffs, *inboxes])
    expected, count = build(
        source, manifest, worksheet, selection_receipt,
        selection, curated, handoffs, replies, inboxes, filter_mode,
        human_ordinals)
    require(all(0 < len(raw) <= LIMIT for raw in expected.values()))
    fd = -1
    try:
        fd = os.open(private_docket_dir, os.O_RDONLY |
                     getattr(os, "O_DIRECTORY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and
                info.st_uid == os.getuid() and
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
    p = argparse.ArgumentParser(
        description="Read-only original source reopen of separate PRIVATE HUMAN follow-up docket")
    for name in ("source", "manifest", "worksheet", "selection-receipt",
                 "selection", "curated-packet", "private-docket-dir"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--private-handoff", action="append", required=True)
    p.add_argument("--round-inbox", action="append", required=True)
    p.add_argument("--round-returned-csv", action="append", required=True)
    p.add_argument("--filter", choices=FILTERS, default="attention")
    p.add_argument("--human-ordinal", action="append", type=int,
                   help="same exact original selected ordinal as original PRIVATE package")
    a = p.parse_args()
    try:
        n = len(a.round_inbox)
        groups = len(a.private_handoff)
        require(2 <= n <= 8 and 1 <= groups <= 3 and
                len(a.round_returned_csv) == n * groups)
        replies = [a.round_returned_csv[i:i+groups]
                   for i in range(0, n * groups, groups)]
        count = reopen(
            a.source, a.manifest, a.worksheet, a.selection_receipt,
            a.selection, a.curated_packet, a.private_handoff, replies,
            a.round_inbox, a.filter, a.human_ordinal or [], a.private_docket_dir)
    except (Hold, OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, MemoryError, RecursionError, csv.Error):
        print("HOLD: PRIVATE HUMAN follow-up not source-identical; no files modified",
              file=sys.stderr)
        return 3
    print("PRIVATE original-source HUMAN docket reopened for " +
          str(count) + " rows; REVIEW ONLY, unsigned, no authority.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
