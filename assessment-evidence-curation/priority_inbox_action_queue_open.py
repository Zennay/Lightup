#!/usr/bin/env python3
"""Read-only local byte-custody reopen for a generated PRIVATE HUMAN action queue.

Checks exact members, strict source-minimal aggregate schema, mode/ownership
and unsigned report/receipt hashes. Original lab source and human identities
are NOT re-admitted by this convenience reopen. Nothing is written.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys

from briefing import json_bytes
from curate import Hold, digest, literal_sha
from packet_open import json_private, read_private
from priority_inbox_action_queue import QUEUE, COUNTS, RECEIPT, STAGES
from priority_reply import UNTRUSTED_FLAGS

FILES = {QUEUE, COUNTS, RECEIPT}
PRIORITIES = {"routine", "soon", "urgent"}


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: PRIVATE HUMAN action queue local custody mismatch")


def reopen(directory: str) -> int:
    dfd = -1
    try:
        dfd = os.open(directory, os.O_RDONLY |
                      getattr(os, "O_DIRECTORY", 0) |
                      getattr(os, "O_NOFOLLOW", 0))
        meta = os.fstat(dfd)
        require(stat.S_ISDIR(meta.st_mode) and
                meta.st_uid == os.getuid() and
                stat.S_IMODE(meta.st_mode) == 0o700 and
                set(os.listdir(dfd)) == FILES)
        receipt_raw = read_private(dfd, RECEIPT, 64 * 1024)
        counts_raw = read_private(dfd, COUNTS, 64 * 1024)
        html_raw = read_private(dfd, QUEUE)
        receipt = json_private(receipt_raw)
        counts = json_private(counts_raw)
        keys = {"schema", "status", "selected_human_count",
                "original_private_inbox_receipt_sha256_unsigned",
                "original_private_inbox_complete_csv_sha256_unsigned",
                "private_action_queue_sha256_unsigned",
                "private_counts_sha256_unsigned", *UNTRUSTED_FLAGS}
        require(set(receipt) == keys and
                receipt["schema"] == "lightup.private_human_action_queue_receipt.v1" and
                receipt["status"] == "REVIEW_ONLY" and
                all(receipt[k] is False for k in UNTRUSTED_FLAGS) and
                receipt_raw == json_bytes(receipt) and
                all(literal_sha(receipt[k]) for k in keys if
                    k.endswith("_sha256_unsigned")))
        require(digest(html_raw) == receipt["private_action_queue_sha256_unsigned"] and
                digest(counts_raw) == receipt["private_counts_sha256_unsigned"])
        count_keys = {"schema", "status", "selected_human_count",
                      "human_stage_counts", "human_priority_stage_counts",
                      *UNTRUSTED_FLAGS}
        require(set(counts) == count_keys and
                counts["schema"] == "lightup.private_human_action_queue_counts.v1" and
                counts["status"] == "REVIEW_ONLY" and
                all(counts[k] is False for k in UNTRUSTED_FLAGS) and
                counts_raw == json_bytes(counts))
        number = counts["selected_human_count"]
        require(type(number) is int and 1 <= number <= 64 and
                receipt["selected_human_count"] == number and
                type(counts["human_stage_counts"]) is dict and
                set(counts["human_stage_counts"]) == {key for key, _ in STAGES} and
                all(type(value) is int and value >= 0
                    for value in counts["human_stage_counts"].values()) and
                sum(counts["human_stage_counts"].values()) == number)
        groups = counts["human_priority_stage_counts"]
        require(type(groups) is dict and 1 <= len(groups) <= 3 and
                set(groups).issubset(PRIORITIES))
        aggregate = {key: 0 for key, _ in STAGES}
        for group in groups.values():
            require(type(group) is dict and set(group) == set(aggregate) and
                    all(type(value) is int and value >= 0 for value in group.values()) and
                    sum(group.values()) > 0)
            for key, value in group.items():
                aggregate[key] += value
        require(aggregate == counts["human_stage_counts"])
        return number
    finally:
        if dfd >= 0:
            os.close(dfd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only owner-private HUMAN action queue byte custody; never authorization")
    parser.add_argument("--private-dir", required=True,
                        help="previously generated private action queue output folder")
    args = parser.parse_args()
    try:
        count = reopen(args.private_dir)
    except (Hold, OSError, ValueError, KeyError, TypeError, UnicodeError,
            RecursionError, OverflowError, MemoryError):
        print("HOLD: PRIVATE HUMAN queue incomplete, malformed or locally modified; "
              "nothing repaired", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN action queue local bytes reopened: " + str(count) +
          " selected HUMAN rows; UNSIGNED REVIEW_ONLY; no original source, "
          "recipient, consent or security finding authenticated.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
