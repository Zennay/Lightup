#!/usr/bin/env python3
"""Reopen one already-published PRIVATE curated packet by its exact local bytes.

No original lab re-admission, source authentication, recipient verification,
finding correctness, approval, network operation or grant is performed.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys

from curate import Hold, UNVERIFIED, digest, literal_sha
from briefing import strict_pairs

MAX_FILE = 24 * 1024 * 1024
MAX_JSON = 64 * 1024
BASE_FILES = {
    "PRIVATE-curated-dossier.html",
    "PRIVATE-packet-directory.html",
    "PRIVATE-source-minimized-HUMAN-handoff.html",
    "PRIVATE-curation-receipt.json",
    "anonymous-counts-PRIVATE.json",
}
PRIORITIES = ("routine", "soon", "urgent")


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: PRIVATE local packet cannot be reopened safely")


def read_private(directory_fd: int, name: str, limit: int = MAX_FILE) -> bytes:
    require(name and "/" not in name and "\\" not in name and name not in (".", ".."))
    fd = -1
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_NONBLOCK", 0), dir_fd=directory_fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
                0 < before.st_size <= limit)
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        require(0 < len(raw) <= limit and len(raw) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
        return raw
    finally:
        if fd >= 0:
            os.close(fd)


def json_private(data: bytes) -> dict:
    obj = json.loads(data.decode("utf-8"), object_pairs_hook=strict_pairs,
                     parse_constant=lambda _: require(False))
    require(type(obj) is dict)
    return obj


def reopen(path: str) -> int:
    dfd = -1
    try:
        dfd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                      getattr(os, "O_NOFOLLOW", 0))
        directory = os.fstat(dfd)
        require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.getuid()
                and stat.S_IMODE(directory.st_mode) == 0o700)
        receipt = json_private(read_private(dfd, "PRIVATE-curation-receipt.json", MAX_JSON))
        needed = {
            "schema", "status", "original_source_sha256_unsigned",
            "human_worksheet_sha256_unsigned", "human_selection_sha256_unsigned",
            "private_curated_dossier_sha256_unsigned",
            "private_packet_directory_sha256_unsigned",
            "anonymous_counts_sha256_unsigned",
            "source_minimized_human_handoff_sha256_unsigned",
            "private_priority_handoff_sha256_unsigned",
            "private_priority_reply_template_sha256_unsigned",
            "selected_original_ordinals", *UNVERIFIED
        }
        require(set(receipt) == needed and
                receipt["schema"] == "lightup.private_curated_lab_receipt.v1" and
                receipt["status"] == "REVIEW_ONLY" and
                all(receipt[k] is False for k in UNVERIFIED))
        for key in needed:
            if key.endswith("_sha256_unsigned"):
                require(literal_sha(receipt[key]))
        ordinals = receipt["selected_original_ordinals"]
        require(type(ordinals) is list and 1 <= len(ordinals) <= 64 and
                all(type(n) is int and 1 <= n <= 10000 for n in ordinals) and
                ordinals == sorted(set(ordinals)))
        grouped = receipt["private_priority_handoff_sha256_unsigned"]
        require(type(grouped) is dict and bool(grouped) and
                set(grouped).issubset(PRIORITIES) and
                all(literal_sha(x) for x in grouped.values()))
        reply_hashes = receipt["private_priority_reply_template_sha256_unsigned"]
        require(type(reply_hashes) is dict and set(reply_hashes) == set(grouped) and
                all(literal_sha(x) for x in reply_hashes.values()))
        actual = set(BASE_FILES) | {
            "PRIVATE-HUMAN-" + priority + "-priority.html" for priority in grouped
        }
        actual |= {
            "PRIVATE-HUMAN-" + priority + "-reply-template.csv"
            for priority in grouped
        }
        require(set(os.listdir(dfd)) == actual)
        hashes = {
            "PRIVATE-curated-dossier.html": "private_curated_dossier_sha256_unsigned",
            "PRIVATE-packet-directory.html": "private_packet_directory_sha256_unsigned",
            "anonymous-counts-PRIVATE.json": "anonymous_counts_sha256_unsigned",
            "PRIVATE-source-minimized-HUMAN-handoff.html":
                "source_minimized_human_handoff_sha256_unsigned",
        }
        for name, key in hashes.items():
            require(digest(read_private(dfd, name)) == receipt[key])
        for priority, wanted in reply_hashes.items():
            name = "PRIVATE-HUMAN-" + priority + "-reply-template.csv"
            require(digest(read_private(dfd, name)) == wanted)
        for priority, wanted in grouped.items():
            name = "PRIVATE-HUMAN-" + priority + "-priority.html"
            require(digest(read_private(dfd, name)) == wanted)
        counts = json_private(read_private(dfd, "anonymous-counts-PRIVATE.json", MAX_JSON))
        require(counts.get("schema") == "lightup.private_curated_lab_aggregate.v1"
                and counts.get("status") == "REVIEW_ONLY"
                and counts.get("human_selected_count") == len(ordinals)
                and type(counts["human_selected_count"]) is int
                and counts.get("source_identifiers_included") is False
                and all(counts.get(flag) is False for flag in UNVERIFIED))
        priorities = counts.get("human_selected_priority_counts")
        require(type(priorities) is dict and set(priorities) == set(PRIORITIES) and
                all(type(value) is int and value >= 0 for value in priorities.values()) and
                sum(priorities.values()) == len(ordinals) and
                set(grouped) == {k for k, v in priorities.items() if v})
        return len(ordinals)
    finally:
        if dfd >= 0:
            os.close(dfd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only PRIVATE packet byte-integrity reopen; NEVER a consent or security verdict")
    parser.add_argument("--private-dir", required=True, help="already-published owner-private curated packet directory")
    args = parser.parse_args()
    try:
        count = reopen(args.private_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError, MemoryError):
        print("HOLD: local PRIVATE packet incomplete or inconsistent; no disclosure authorised", file=sys.stderr)
        return 3
    print("PRIVATE packet byte consistency: REVIEW_ONLY; HUMAN-selected entries: " + str(count) +
          ". UNSIGNED; originals, recipient, consent, scope and findings NOT verified.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
