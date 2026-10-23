#!/usr/bin/env python3
"""Reopen PRIVATE interactive HUMAN receiver studio without the original report.

Checks only local byte/renderer consistency against current trusted product
code, never authenticates the originating client, source, signature or consent.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

import recipient_studio as studio

review = studio.review
workspace = studio.workspace
triage = studio.triage
verify = studio.verify
read_cockpit = studio.trend.read_cockpit

EXPECTED = frozenset(("index.html", "source-free.json", "manifest.json"))
MANIFEST = frozenset(("kind", "schema_version", "disposition",
                      "warning", "files", *review.FLAGS))
SEED = frozenset(("kind", "schema_version", "disposition", "warning",
                  "source_sha256", "reasons"))
ROW = frozenset(("reason", "count", "delta", "advice"))


def admit_seed(seed: object) -> dict:
    review.require(type(seed) is dict and set(seed) == SEED and
                   seed.get("kind") == studio.KIND and
                   type(seed.get("schema_version")) is int and
                   seed["schema_version"] == 1 and
                   seed.get("disposition") == studio.DISPOSITION and
                   seed.get("warning") == studio.WARNING and
                   type(seed.get("source_sha256")) is str and
                   review.HEX.fullmatch(seed["source_sha256"]) is not None,
                   "Unknown source-free HUMAN studio data contract")
    rows = seed.get("reasons")
    expected = sorted(triage.REASONS)
    review.require(type(rows) is list and len(rows) == len(expected),
                   "HUMAN reason groups incomplete or unknown")
    for key, row in zip(expected, rows):
        review.require(type(row) is dict and set(row) == ROW and
                       type(row.get("reason")) is str and row["reason"] == key and
                       type(row.get("count")) is int and
                       0 <= row["count"] <= 100000 and
                       type(row.get("delta")) is int and
                       -100000 <= row["delta"] <= 100000 and
                       type(row.get("advice")) is str and
                       row["advice"] == studio.board.ADVICE[key],
                       "HUMAN reason text or source-only count was altered")
    return seed


def inspect(folder: Path) -> dict:
    review.require(folder.is_absolute() and not folder.is_symlink() and
                   folder.parent == folder.parent.resolve(strict=True),
                   "PRIVATE recipient HTML workroom must use literal path")
    meta = folder.stat(follow_symlinks=False)
    review.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
                   meta.st_mode & 0o077 == 0 and
                   {item.name for item in folder.iterdir()} == EXPECTED,
                   "Received source-free HUMAN studio has unsafe/missing files")
    mraw = review.private_read(folder / "manifest.json")
    m = verify.json_obj(mraw)
    review.require(type(m) is dict and set(m) == MANIFEST and
                   m.get("kind") == studio.KIND + ".local_receipt" and
                   type(m.get("schema_version")) is int and
                   m["schema_version"] == 1 and
                   m.get("disposition") == studio.DISPOSITION and
                   m.get("warning") == studio.WARNING and
                   all(m.get(flag) is False for flag in review.FLAGS) and
                   type(m.get("files")) is dict and
                   set(m["files"]) == EXPECTED - {"manifest.json"} and
                   mraw == workspace.pretty(m),
                   "Unknown owner-private local HUMAN studio inventory")
    raw = {}
    for name in sorted(EXPECTED - {"manifest.json"}):
        info = m["files"][name]
        review.require(type(info) is dict and
                       set(info) == {"bytes", "sha256"} and
                       type(info.get("sha256")) is str and
                       review.HEX.fullmatch(info["sha256"]) is not None,
                       "Malformed HUMAN interactive product checksum")
        n = read_cockpit.nonnegative(info.get("bytes"),
                                    "private HUMAN studio asset bytes",
                                    verify.MAX_BYTES)
        blob = review.private_read(folder / name)
        review.require(len(blob) == n and
                       hashlib.sha256(blob).hexdigest() == info["sha256"],
                       "Native private HUMAN studio asset bytes altered")
        raw[name] = blob
    seed = admit_seed(verify.json_obj(raw["source-free.json"]))
    review.require(raw == studio.artifacts(seed),
                   "Interactive HUMAN HTML differs from native CSP-pinned renderer")
    review.require(review.private_read(folder / "manifest.json") == mraw,
                   "HUMAN studio manifest changed during admission")
    for name, original in raw.items():
        review.require(review.private_read(folder / name) == original,
                       "HUMAN studio asset changed during read-only admission")
    return {"human_reason_groups": len(seed["reasons"]),
            "accepted_source_free_files": len(EXPECTED),
            "original_sender_authenticated": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Review local generated PRIVATE HUMAN studio byte/render consistency "
        "before opening it in a trusted browser; no source authentication"))
    parser.add_argument("--folder", type=Path, required=True,
                        help="Complete received owner-private 0700 HUMAN studio directory")
    args = parser.parse_args()
    try:
        data = inspect(args.folder)
        print("REVIEW_ONLY: private HUMAN interactive studio locally consistent; " +
              str(data["human_reason_groups"]) +
              " original human reason groups. Sender authenticity UNKNOWN.")
        return 2
    except (review.Hold, OSError, UnicodeError, ValueError):
        print("HOLD: native PRIVATE HUMAN interactive studio is incomplete/altered.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
