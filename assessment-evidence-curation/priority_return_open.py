#!/usr/bin/env python3
"""Read-only local integrity reopen for one PRIVATE HUMAN recipient response packet.

Unsigned local byte-consistency check only; no verification, recipient
authentication, authority, consent, disclosure, source admission or dispatch.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys

from curate import Hold, digest, literal_sha
from packet_open import MAX_JSON, json_private, read_private
from priority_reply import REPORT, COUNTS, RECEIPT_OUT, UNTRUSTED_FLAGS
from response import STAGES

def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: incomplete or inconsistent private HUMAN response packet")

def reopen(folder: str) -> int:
    dfd = -1
    try:
        dfd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                      getattr(os, "O_NOFOLLOW", 0))
        meta = os.fstat(dfd)
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid()
                and stat.S_IMODE(meta.st_mode) == 0o700)
        require(set(os.listdir(dfd)) == {REPORT, COUNTS, RECEIPT_OUT})
        receipt = json_private(read_private(dfd, RECEIPT_OUT, MAX_JSON))
        fields = {
            "schema", "status", "original_handoff_receipt_sha256_unsigned",
            "original_blank_response_template_sha256_unsigned",
            "human_returned_csv_sha256_unsigned",
            "private_human_report_sha256_unsigned",
            "private_human_counts_sha256_unsigned",
            "human_reply_row_count", *UNTRUSTED_FLAGS,
        }
        require(set(receipt) == fields and
                receipt["schema"] == "lightup.private_priority_human_return.v1" and
                receipt["status"] == "REVIEW_ONLY"
                and all(receipt[k] is False for k in UNTRUSTED_FLAGS))
        require(all(literal_sha(receipt[k]) for k in fields
                    if k.endswith("_sha256_unsigned")))
        count = receipt["human_reply_row_count"]
        require(type(count) is int and 1 <= count <= 64)
        raw = read_private(dfd, COUNTS, MAX_JSON)
        require(digest(raw) == receipt["private_human_counts_sha256_unsigned"])
        summary = json_private(raw)
        require(set(summary) == {"schema", "status", "human_reply_row_count",
                                "human_recipient_stage_counts", *UNTRUSTED_FLAGS})
        require(summary["schema"] == "lightup.private_priority_human_return_counts.v1"
                and summary["status"] == "REVIEW_ONLY"
                and type(summary["human_reply_row_count"]) is int
                and summary["human_reply_row_count"] == count
                and all(summary[k] is False for k in UNTRUSTED_FLAGS))
        stages = summary["human_recipient_stage_counts"]
        require(type(stages) is dict and
                set(stages) == {s or "no_human_response" for s in STAGES}
                and all(type(v) is int and v >= 0 for v in stages.values())
                and sum(stages.values()) == count)
        require(digest(read_private(dfd, REPORT)) ==
                receipt["private_human_report_sha256_unsigned"])
        return count
    finally:
        if dfd >= 0:
            os.close(dfd)

def main() -> int:
    ap = argparse.ArgumentParser(description="PRIVATE HUMAN return local unsigned byte reopen only")
    ap.add_argument("--private-dir", required=True)
    args = ap.parse_args()
    try:
        count = reopen(args.private_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError,
            OverflowError, UnicodeError, RecursionError, MemoryError):
        print("HOLD: private HUMAN local packet inconsistent; no permission", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN return bytes consistent: " + str(count) +
          " HUMAN rows; UNSIGNED, NOT verified, no consent or grant.")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
