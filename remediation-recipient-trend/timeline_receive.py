#!/usr/bin/env python3
"""Strict offline reopening of ONE self-contained unsigned HUMAN series receipt.

Checks native aggregate shapes, exact per-slot signed arithmetic and original
HTML/CSV/Markdown bytes. No underlying customer/source data required.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

import recipient_workload_series as timeline
import receive

review = timeline.review
workspace = timeline.workspace
verify = timeline.verify
read_cockpit = timeline.read_cockpit

OUTPUTS = frozenset(("index.html", "series.json", "series.csv",
                     "human-followup.md", "manifest.json"))
TOP = frozenset(("kind", "schema_version", "disposition", "warning",
                 "ordering", "cohort_identity", "snapshots",
                 "adjacent_user_order_deltas", *review.FLAGS))
RECEIPT = frozenset(("kind", "schema_version", "disposition",
                     "warning", "files", *review.FLAGS))


def admit_doc(doc: object) -> None:
    review.require(type(doc) is dict and set(doc) == TOP and
                   doc.get("kind") == timeline.KIND and
                   type(doc.get("schema_version")) is int and
                   doc["schema_version"] == 1 and
                   doc.get("disposition") == "UNVERIFIED_HUMAN_COUNTS_ONLY" and
                   doc.get("warning") == timeline.WARNING and
                   doc.get("ordering") == timeline.ORDERING and
                   doc.get("cohort_identity") == timeline.COHORT and
                   all(doc.get(flag) is False for flag in review.FLAGS),
                   "Invalid original HUMAN time-series authority or schema")
    snapshots = doc.get("snapshots")
    deltas = doc.get("adjacent_user_order_deltas")
    review.require(type(snapshots) is list and
                   timeline.MIN_SNAPSHOTS <= len(snapshots) <= timeline.MAX_SNAPSHOTS and
                   type(deltas) is list and len(deltas) == len(snapshots) - 1,
                   "Incomplete or excessive original packet ordinals")
    for idx, entry in enumerate(snapshots, 1):
        review.require(type(entry) is dict and
                       set(entry) == {"ordinal", "counts"} and
                       type(entry["ordinal"]) is int and entry["ordinal"] == idx,
                       "Invalid/reordered original source-free ordinal")
        receive.valid_snapshot(entry["counts"])
    for idx, row in enumerate(deltas, 1):
        review.require(type(row) is dict and
                       set(row) == {"from_ordinal", "to_ordinal",
                                    "delta_right_minus_left"} and
                       type(row["from_ordinal"]) is int and
                       type(row["to_ordinal"]) is int and
                       row["from_ordinal"] == idx and row["to_ordinal"] == idx + 1,
                       "Invalid or forged adjacent ordinal")
        a, b = snapshots[idx - 1]["counts"], snapshots[idx]["counts"]
        expected = timeline.trend.difference(a, b)
        delta = row["delta_right_minus_left"]
        review.require(type(delta) is dict and
                       set(delta) == set(expected) and
                       all(type(delta[k]) is int for k in timeline.trend.FIELDS) and
                       type(delta["stages"]) is dict and
                       set(delta["stages"]) == set(timeline.triage.STAGES) and
                       type(delta["reasons"]) is dict and
                       set(delta["reasons"]) == set(timeline.triage.REASONS) and
                       all(type(v) is int for v in delta["stages"].values()) and
                       all(type(v) is int for v in delta["reasons"].values()) and
                       delta == expected,
                       "Forged noninteger or incompatible HUMAN count difference")


def inspect(folder: Path) -> dict:
    review.require(folder.is_absolute() and not folder.is_symlink() and
                   folder.parent == folder.parent.resolve(strict=True),
                   "Original private HUMAN receipt must be literal")
    meta = folder.stat(follow_symlinks=False)
    review.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
                   meta.st_mode & 0o077 == 0 and
                   {p.name for p in folder.iterdir()} == OUTPUTS,
                   "Native owner-private HUMANS-only receipt inventory incomplete")
    mraw = review.private_read(folder / "manifest.json")
    manifest = verify.json_obj(mraw)
    review.require(type(manifest) is dict and set(manifest) == RECEIPT and
                   manifest.get("kind") == timeline.KIND + ".local_receipt" and
                   type(manifest.get("schema_version")) is int and
                   manifest["schema_version"] == 1 and
                   manifest.get("disposition") == "UNVERIFIED_HUMAN_COUNTS_ONLY" and
                   manifest.get("warning") == timeline.WARNING and
                   all(manifest.get(flag) is False for flag in review.FLAGS) and
                   mraw == workspace.pretty(manifest) and
                   type(manifest.get("files")) is dict and
                   set(manifest["files"]) == OUTPUTS - {"manifest.json"},
                   "Invalid local private source-free series manifest")
    raw = {}
    for filename in sorted(OUTPUTS - {"manifest.json"}):
        desc = manifest["files"][filename]
        review.require(type(desc) is dict and
                       set(desc) == {"bytes", "sha256"} and
                       type(desc["sha256"]) is str and
                       review.HEX.fullmatch(desc["sha256"]) is not None,
                       "Invalid manifest entry for series file")
        n = read_cockpit.nonnegative(desc["bytes"], "series file",
                                    verify.MAX_BYTES)
        data = review.private_read(folder / filename)
        review.require(len(data) == n and
                       hashlib.sha256(data).hexdigest() == desc["sha256"],
                       "Original private series file checksum inconsistency")
        raw[filename] = data
    source_free = verify.json_obj(raw["series.json"])
    admit_doc(source_free)
    review.require(raw == timeline.artifacts(source_free),
                   "Series HTML/JSON/CSV/HUMAN brief differs from native exact rendering")
    review.require(review.private_read(folder / "manifest.json") == mraw,
                   "Series receipt changed during reading")
    for filename, payload in raw.items():
        review.require(review.private_read(folder / filename) == payload,
                       "Series file replaced during read-only reopen")
    return {
        "packet_count": len(source_free["snapshots"]),
        "final_pending_human": source_free["snapshots"][-1]["counts"]["pending"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Verify one complete local PRIVATE source-free multi-packet HUMAN "
        "workload receipt without original customer/evidence sources"))
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = inspect(args.receipt)
        print("REVIEW_ONLY: unsigned local HUMAN series receipt is internally consistent; " +
              str(result["packet_count"]) + " owner-selected packets, " +
              str(result["final_pending_human"]) +
              " pending in the last handoff. NOT authenticated chronology/fixes.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: local HUMAN series receipt invalid or incomplete; "
              "no permission/fix attestation.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
