#!/usr/bin/env python3
"""Read-only full-lineage reopen for a selected PRIVATE HUMAN revision delta."""
from __future__ import annotations

import argparse
import csv
import os
import stat
import sys

from curate import Hold
from packet_open import MAX_FILE, read_private
from priority_inbox import ensure_output_outside_inputs
from priority_inbox_stage_brief_diff import build


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: selected PRIVATE HUMAN stage/priority delta drifted")


def reopen(source: str, manifest: str, worksheet: str, selection_receipt: str,
           selection: str, curated: str, handoffs: list[str],
           before_replies: list[str], before_inbox: str,
           after_replies: list[str], after_inbox: str,
           stage: str, priority: str, saved_dir: str) -> int:
    ensure_output_outside_inputs(
        saved_dir, [curated, *handoffs, before_inbox, after_inbox])
    try:
        expected, changed = build(
            source, manifest, worksheet, selection_receipt, selection,
            curated, handoffs, before_replies, before_inbox,
            after_replies, after_inbox, stage, priority)
    except Hold:
        raise Hold("HOLD: original source or before/after inbox admission failed") from None
    require(bool(expected) and all(0 < len(raw) <= MAX_FILE for raw in expected.values()))
    dfd = -1
    try:
        dfd = os.open(saved_dir, os.O_RDONLY |
                      getattr(os, "O_DIRECTORY", 0) |
                      getattr(os, "O_NOFOLLOW", 0))
        meta = os.fstat(dfd)
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
                stat.S_IMODE(meta.st_mode) == 0o700)
        require(set(os.listdir(dfd)) == set(expected))
        for name, wanted in expected.items():
            require(read_private(dfd, name, max(1, len(wanted))) == wanted)
        return changed
    finally:
        if dfd >= 0:
            os.close(dfd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only exact-source reopen of a selected PRIVATE HUMAN delta")
    for key in ("source", "manifest", "worksheet", "selection-receipt", "selection",
                "curated-packet", "before-private-inbox", "after-private-inbox",
                "private-delta-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--before-returned-csv", action="append", required=True)
    parser.add_argument("--after-returned-csv", action="append", required=True)
    parser.add_argument("--human-stage", required=True)
    parser.add_argument("--human-priority", required=True)
    args = parser.parse_args()
    try:
        count = reopen(
            args.source, args.manifest, args.worksheet, args.selection_receipt,
            args.selection, args.curated_packet, args.private_handoff,
            args.before_returned_csv, args.before_private_inbox,
            args.after_returned_csv, args.after_private_inbox,
            args.human_stage, args.human_priority, args.private_delta_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError, csv.Error):
        print("HOLD: selected PRIVATE HUMAN delta or original source drifted; "
              "nothing changed", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN selected stage/priority delta reopened from exact original "
          "source and inbox bytes: " + str(count) +
          " changed rows; unsigned REVIEW_ONLY, no authority.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
