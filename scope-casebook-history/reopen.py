#!/usr/bin/env python3
"""Read-only original-source HUMAN Casebook history reopen.

Re-admits exactly selected original source files and independently regenerates
all outputs byte-for-byte before viewing. It is NOT a security attestation,
authenticated source proof, approval, grant, revocation or execution permit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from history import (
    Hold, fail, generate, pairs_no_duplicates, read_private, selected_original_files,
)

FILES = {
    "workroom.html", "workroom-current-template.csv", "index.html", "anonymous.html", "anonymous-counts.json",
    "anonymous-counts.csv", "private-source-changes.csv",
    "human-followup.txt", "private-source-inventory.json",
    "private-human-case-queue.csv",
    "private-human-review-template.csv",
    "private-human-case-transitions.csv",
    "private-original-case-details.csv",
    "anonymous-source-order.csv",
    "anonymous-human-actions.csv",
}


def strictly_read_output(directory: Path, filename: str) -> bytes:
    fd = os.open(directory / filename, os.O_RDONLY |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(fd)
        fail(stat.S_ISREG(info.st_mode) and info.st_mode & 0o077 == 0
             and info.st_size <= 8_388_608, "private output unavailable")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(8_388_609)
        fail(len(raw) <= 8_388_608, "private output exceeds bound")
        return raw
    finally:
        os.close(fd)


def inspect(folder: Path, inputs: list[Path]) -> None:
    fail(2 <= len(inputs) <= 12, "requires 2-12 source packets")
    info = folder.lstat()
    fail(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
         and info.st_mode & 0o077 == 0, "private folder refused")
    fail({p.name for p in folder.iterdir()} == FILES,
         "private output inventory differs")
    documents_and_bytes = [read_private(p) for p in inputs]
    docs = [x[0] for x in documents_and_bytes]
    fail(all(doc["client_id"] == docs[0]["client_id"] for doc in docs),
         "selected source tenants differ")

    inventory_bytes = strictly_read_output(folder, "private-source-inventory.json")
    try:
        inventory = json.loads(inventory_bytes.decode("utf-8", errors="strict"),
                               object_pairs_hook=pairs_no_duplicates)
    except (json.JSONDecodeError, UnicodeError):
        raise Hold("private manifest malformed") from None
    fail(type(inventory) is dict and set(inventory) == {
        "kind", "version", "disposition", "authority",
        "source_authenticated", "snapshots"
    }, "private source manifest shape changed")
    fail(inventory["kind"] == "lightup.casebook_private_source_inventory"
         and type(inventory["version"]) is int and inventory["version"] == 1
         and inventory["disposition"] == "HUMAN_REVIEW_ONLY_HOLD"
         and inventory["authority"] is False
         and inventory["source_authenticated"] is False
         and type(inventory["snapshots"]) is list
         and len(inventory["snapshots"]) == len(docs),
         "private source inventory invalid")
    for ordinal, (row, (_, source_bytes)) in enumerate(
        zip(inventory["snapshots"], documents_and_bytes), start=1
    ):
        fail(type(row) is dict and set(row) ==
             {"ordinal", "source_sha256", "source_bytes"}
             and type(row["ordinal"]) is int and row["ordinal"] == ordinal
             and type(row["source_bytes"]) is int
             and row["source_bytes"] == len(source_bytes)
             and type(row["source_sha256"]) is str
             and row["source_sha256"] == hashlib.sha256(source_bytes).hexdigest(),
             "private source bytes or selected ordinal changed")

    expected = generate(docs)
    # Original canonical generated inventory is deterministic and private.
    expected["private-source-inventory.json"] = (
        json.dumps(inventory, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    for filename in FILES:
        fail(strictly_read_output(folder, filename) == expected[filename],
             "private output changed or generated source version differs")


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only exact original private Casebook history reopen")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--input", type=Path, action="append",
                           help="Same original private packets in SAME ordinal order")
    selection.add_argument("--packet-dir", type=Path,
                           help="Same exact PRIVATE casebook-01.json...-12.json folder")
    parser.add_argument("--history-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        paths = selected_original_files(args.input, args.packet_dir)
        fail(len({str(p.absolute()) for p in paths}) == len(paths),
             "duplicate original packet path")
        inspect(args.history_dir, paths)
    except (Hold, OSError, ValueError, TypeError, KeyError):
        print("HOLD: original PRIVATE history cannot be reopened from selected bytes; "
              "NO approval or authority.", file=sys.stderr)
        return 3
    print("REVIEW_ONLY: selected original bytes match this PRIVATE human history "
          "and generated files; NOT a signature, consent, scan, grant, verdict or release.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
