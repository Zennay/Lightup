#!/usr/bin/env python3
"""Read-only full-source-lineage reopen for a selected PRIVATE HUMAN briefing.

Rebuilds the chosen stage/priority brief from the exact original lab source,
selection, every priority handoff/return and complete saved inbox. Compares
the owner-private saved output byte-for-byte; never repairs or writes.
"""
from __future__ import annotations

import argparse
import csv
import os
import stat
import sys

from curate import Hold
from packet_open import MAX_FILE, read_private
from priority_inbox_stage_brief import (
    BRIEF, COUNTS, RECEIPT, PRIORITIES, STAGES, build,
)


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: selected PRIVATE HUMAN brief does not match current source lineage")


def reopen(source: str, manifest: str, worksheet: str, selection_receipt: str,
           selection: str, curated_packet: str, handoffs: list[str],
           replies: list[str], inbox: str, stage: str, priority: str,
           private_dir: str) -> int:
    require(stage in dict(STAGES) and priority in PRIORITIES)
    expected, count = build(
        source, manifest, worksheet, selection_receipt, selection,
        curated_packet, handoffs, replies, inbox, stage, priority)
    require(bool(expected) and set(expected) == {BRIEF, COUNTS, RECEIPT} and
            all(0 < len(raw) <= MAX_FILE for raw in expected.values()))
    dfd = -1
    try:
        dfd = os.open(private_dir, os.O_RDONLY |
                      getattr(os, "O_DIRECTORY", 0) |
                      getattr(os, "O_NOFOLLOW", 0))
        meta = os.fstat(dfd)
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
                stat.S_IMODE(meta.st_mode) == 0o700)
        actual = set(os.listdir(dfd))
        require(actual == set(expected))
        for name, wanted in expected.items():
            current = read_private(dfd, name, max(1, len(wanted)))
            require(current == wanted)
        return count
    finally:
        if dfd >= 0:
            os.close(dfd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only full-source reopen of one PRIVATE HUMAN stage/priority brief")
    for name in ("source", "manifest", "worksheet", "selection-receipt",
                 "selection", "curated-packet", "private-inbox", "private-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--returned-csv", action="append", required=True)
    parser.add_argument("--human-stage", choices=[key for key, _ in STAGES],
                        required=True)
    parser.add_argument("--human-priority", choices=PRIORITIES, required=True)
    args = parser.parse_args()
    try:
        count = reopen(
            args.source, args.manifest, args.worksheet, args.selection_receipt,
            args.selection, args.curated_packet, args.private_handoff,
            args.returned_csv, args.private_inbox, args.human_stage,
            args.human_priority, args.private_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError, csv.Error):
        print("HOLD: selected PRIVATE HUMAN brief, original source or inbox drifted; "
              "nothing changed", file=sys.stderr)
        return 3
    print("PRIVATE selected HUMAN stage/priority brief reopened against exact "
          "original source and inbox bytes: " + str(count) +
          " rows; unsigned REVIEW_ONLY, no consent or authority.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
