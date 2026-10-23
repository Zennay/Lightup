#!/usr/bin/env python3
"""Read-only full-source-lineage reopen for the selected HUMAN timeline."""
from __future__ import annotations

import argparse
import csv
import os
import stat
import sys

from curate import Hold
from packet_open import MAX_FILE, read_private
from priority_inbox import ensure_output_outside_inputs
from priority_inbox_stage_brief_timeline import build


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: PRIVATE HUMAN timeline no longer matches original lineage")


def reopen(source: str, manifest: str, worksheet: str, selection_receipt: str,
           selection: str, curated: str, handoffs: list[str],
           round_replies: list[list[str]], round_inboxes: list[str],
           stage: str, priority: str, saved_dir: str) -> int:
    ensure_output_outside_inputs(saved_dir, [curated, *handoffs, *round_inboxes])
    try:
        expected, count = build(
            source, manifest, worksheet, selection_receipt, selection,
            curated, handoffs, round_replies, round_inboxes, stage, priority)
    except Hold:
        raise Hold("HOLD: original source or one ordered inbox revision failed admission") from None
    require(bool(expected) and all(0 < len(raw) <= MAX_FILE for raw in expected.values()))
    dfd = -1
    try:
        dfd = os.open(saved_dir, os.O_RDONLY |
                      getattr(os, "O_DIRECTORY", 0) |
                      getattr(os, "O_NOFOLLOW", 0))
        meta = os.fstat(dfd)
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
                stat.S_IMODE(meta.st_mode) == 0o700 and
                set(os.listdir(dfd)) == set(expected))
        for name, wanted in expected.items():
            require(read_private(dfd, name, max(1, len(wanted))) == wanted)
        return count
    finally:
        if dfd >= 0:
            os.close(dfd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only source-bound reopen of one PRIVATE HUMAN timeline")
    for key in ("source", "manifest", "worksheet", "selection-receipt",
                "selection", "curated-packet", "private-timeline-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--round-inbox", action="append", required=True)
    parser.add_argument("--round-returned-csv", action="append", required=True)
    parser.add_argument("--human-stage", required=True)
    parser.add_argument("--human-priority", required=True)
    args = parser.parse_args()
    try:
        rounds = len(args.round_inbox)
        groups = len(args.private_handoff)
        if not 2 <= rounds <= 8 or len(args.round_returned_csv) != rounds * groups:
            raise Hold("HOLD: inbox and return inputs do not form 2–8 complete rounds")
        reply_groups = [args.round_returned_csv[i:i + groups]
                        for i in range(0, len(args.round_returned_csv), groups)]
        count = reopen(
            args.source, args.manifest, args.worksheet, args.selection_receipt,
            args.selection, args.curated_packet, args.private_handoff,
            reply_groups, args.round_inbox, args.human_stage,
            args.human_priority, args.private_timeline_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError, csv.Error):
        print("HOLD: selected PRIVATE HUMAN timeline or original source drifted; "
              "nothing changed", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN timeline reopened from exact source and inbox bytes: " +
          str(count) + " original ordinals; operator order only, unsigned REVIEW_ONLY.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
