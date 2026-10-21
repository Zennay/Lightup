#!/usr/bin/env python3
"""Read-only source-bound reopen for a PRIVATE HUMAN response delta report."""
from __future__ import annotations

import argparse
import os
import stat
import sys

from curate import Hold
from packet_open import MAX_FILE, read_private
from priority_inbox import ensure_output_outside_inputs
from priority_inbox_diff import build


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: PRIVATE HUMAN response delta does not match current source lineage")


def reopen(source_path: str, manifest_path: str, worksheet_path: str,
           selection_receipt: str, selection_path: str, curated_dir: str,
           handoff_paths: list[str], before_reply_paths: list[str],
           before_dir: str, after_reply_paths: list[str], after_dir: str,
           delta_dir: str) -> int:
    ensure_output_outside_inputs(
        delta_dir, [curated_dir, *handoff_paths, before_dir, after_dir])
    try:
        expected, count = build(
            source_path, manifest_path, worksheet_path, selection_receipt,
            selection_path, curated_dir, handoff_paths, before_reply_paths,
            before_dir, after_reply_paths, after_dir)
    except Hold:
        raise Hold("HOLD: original source or one before/after HUMAN inbox failed admission; no files changed") from None
    require(bool(expected) and all(0 < len(raw) <= MAX_FILE for raw in expected.values()))
    dfd = -1
    try:
        dfd = os.open(delta_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                      getattr(os, "O_NOFOLLOW", 0))
        meta = os.fstat(dfd)
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
                stat.S_IMODE(meta.st_mode) == 0o700)
        actual = set(os.listdir(dfd))
        if actual != set(expected):
            missing = sorted(set(expected) - actual)
            extra = sorted(actual - set(expected))
            details = []
            if missing:
                details.append("missing=" + ",".join(missing))
            if extra:
                details.append("unexpected=" + ",".join(extra))
            raise Hold("HOLD: PRIVATE delta inventory drift (" + "; ".join(details) + "); no files changed")
        drift = []
        for name, wanted in expected.items():
            try:
                current = read_private(dfd, name, max(1, len(wanted)))
            except (Hold, OSError):
                drift.append(name + " (missing, unreadable or wrong owner/mode)")
                continue
            if current != wanted:
                drift.append(name + " (bytes differ from current source rebuild)")
        if drift:
            raise Hold("HOLD: PRIVATE delta drift in " + "; ".join(drift) + "; no files changed")
        return count
    finally:
        if dfd >= 0:
            os.close(dfd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reopen a PRIVATE response delta against both original-source HUMAN revisions")
    for key in ("source", "manifest", "worksheet", "selection-receipt",
                "selection", "curated-packet", "before-private-dir",
                "after-private-dir", "delta-private-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--before-returned-csv", action="append", required=True)
    parser.add_argument("--after-returned-csv", action="append", required=True)
    args = parser.parse_args()
    try:
        count = reopen(args.source, args.manifest, args.worksheet,
                       args.selection_receipt, args.selection, args.curated_packet,
                       args.private_handoff, args.before_returned_csv,
                       args.before_private_dir, args.after_returned_csv,
                       args.after_private_dir, args.delta_private_dir)
    except Hold as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError):
        print("HOLD: PRIVATE HUMAN response delta could not be reopened; no files changed",
              file=sys.stderr)
        return 3
    print("PRIVATE source-bound HUMAN response delta reopened: " + str(count) +
          " changed rows; UNSIGNED / REVIEW_ONLY / no authorization.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
