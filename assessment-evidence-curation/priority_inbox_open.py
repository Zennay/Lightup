#!/usr/bin/env python3
"""Read-only full-lineage reopen for the complete PRIVATE original HUMAN inbox.

Re-admits original source, selection, full curated packet, every unique priority
handoff and every returned CSV; deterministically regenerates expected files
in memory and byte-compares the existing private inbox. No write/repair occurs.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys

from curate import Hold
from packet_open import MAX_FILE, read_private
from priority_inbox import build


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: PRIVATE HUMAN inbox does not match current original source lineage")


def reopen_expected(source_path: str, manifest_path: str, worksheet_path: str,
           selection_receipt: str, selection_path: str, curated_dir: str,
           handoff_paths: list[str], reply_paths: list[str],
           private_dir: str) -> tuple[dict[str, bytes], int]:
    try:
        expected, count = build(
            source_path, manifest_path, worksheet_path, selection_receipt,
            selection_path, curated_dir, handoff_paths, reply_paths)
    except Hold:
        raise Hold("HOLD: original source/selection/priority handoff/response admission failed; no files changed") from None
    require(bool(expected) and all(0 < len(raw) <= MAX_FILE for raw in expected.values()))
    dfd = -1
    try:
        dfd = os.open(private_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                      getattr(os, "O_NOFOLLOW", 0))
        meta = os.fstat(dfd)
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
                stat.S_IMODE(meta.st_mode) == 0o700)
        actual = set(os.listdir(dfd))
        if actual != set(expected):
            missing = sorted(set(expected) - actual)
            extra = sorted(actual - set(expected))
            detail = []
            if missing:
                detail.append("missing=" + ",".join(missing))
            if extra:
                detail.append("unexpected=" + ",".join(extra))
            raise Hold("HOLD: PRIVATE inbox inventory drift (" + "; ".join(detail) + "); no files changed")
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
            raise Hold("HOLD: PRIVATE inbox drift in " + "; ".join(drift) + "; no files changed")
        return expected, count
    finally:
        if dfd >= 0:
            os.close(dfd)


def reopen(source_path: str, manifest_path: str, worksheet_path: str,
           selection_receipt: str, selection_path: str, curated_dir: str,
           handoff_paths: list[str], reply_paths: list[str],
           private_dir: str) -> int:
    _, count = reopen_expected(source_path, manifest_path, worksheet_path,
                               selection_receipt, selection_path, curated_dir,
                               handoff_paths, reply_paths, private_dir)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only full-original-source PRIVATE HUMAN inbox reopen; unsigned, never authorizes")
    for key in ("source", "manifest", "worksheet", "selection-receipt",
                "selection", "curated-packet", "private-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True,
                        help="original PRIVATE priority handoff; repeat for every nonempty priority")
    parser.add_argument("--returned-csv", action="append", required=True,
                        help="exact corresponding HUMAN return CSV; repeat in matching handoff order")
    args = parser.parse_args()
    try:
        count = reopen(args.source, args.manifest, args.worksheet,
                       args.selection_receipt, args.selection,
                       args.curated_packet, args.private_handoff,
                       args.returned_csv, args.private_dir)
    except Hold as exc:
        # Error text contains only static gate descriptions and artifact filenames,
        # never original questions, target values, evidence or recipient replies.
        print(str(exc), file=sys.stderr)
        return 3
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError):
        print("HOLD: PRIVATE inbox could not be reopened; no files changed",
              file=sys.stderr)
        return 3
    print("PRIVATE original-source HUMAN inbox reopened by exact deterministic bytes: " +
          str(count) + " selected rows; UNSIGNED / REVIEW_ONLY / no consent or dispatch.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
