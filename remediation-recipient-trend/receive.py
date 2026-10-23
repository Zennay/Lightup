#!/usr/bin/env python3
"""Reopen the original recipient-only aggregate comparison without source packets.

Local byte/render consistency ONLY, no signature, original-source claim or
release authority. Does not contact a network or modify either snapshot.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

import trend

review = trend.review
workspace = trend.workspace
read_cockpit = trend.read_cockpit
verify = trend.verify
triage = trend.triage

FIELDS = frozenset(("kind", "schema_version", "disposition", "warning",
                    "comparison", "cohort_match", "left", "right",
                    "delta_right_minus_left", *review.FLAGS))
MANIFEST = frozenset(("kind", "schema_version", "disposition",
                      "warning", "files", *review.FLAGS))
STATS = frozenset((*trend.FIELDS, "stages", "reasons"))
OUTPUTS = frozenset(("index.html", "counts.json", "counts.csv",
                     "recipient-actions.md", "manifest.json"))


def valid_snapshot(snapshot: object) -> None:
    review.require(type(snapshot) is dict and set(snapshot) == STATS,
                   "Unexpected HUMAN aggregate fields")
    for key in trend.FIELDS:
        read_cockpit.nonnegative(snapshot[key], key, 24000)
    read_cockpit.counts(snapshot["stages"], triage.STAGES, "stages")
    read_cockpit.counts(snapshot["reasons"], triage.REASONS, "reasons")
    review.require(snapshot["slots"] in range(1, 13) and
                   snapshot["questions"] <= 24000 and
                   snapshot["questions"] == sum(snapshot["stages"].values()) and
                   snapshot["pending"] == snapshot["questions"] -
                   snapshot["stages"]["answered_human"] and
                   snapshot["shared_sha_groups"] <= snapshot["local_attachment_links"] and
                   snapshot["human_attention_groups"] <= snapshot["shared_sha_groups"],
                   "Impossible local HUMAN workload counts")


def valid_report(report: object) -> None:
    review.require(type(report) is dict and set(report) == FIELDS and
                   report.get("kind") == trend.KIND and
                   type(report.get("schema_version")) is int and
                   report["schema_version"] == 1 and
                   report.get("disposition") == "UNVERIFIED_HUMAN_COUNTS_ONLY" and
                   report.get("warning") == trend.WARNING and
                   report.get("comparison") ==
                   "operator_selected_left_to_right_not_proven_time" and
                   report.get("cohort_match") == "UNKNOWN_NOT_SOURCE_AUTHENTICATED" and
                   all(report.get(flag) is False for flag in review.FLAGS),
                   "Invalid original unsigned recipient comparison schema")
    valid_snapshot(report["left"])
    valid_snapshot(report["right"])
    delta = report["delta_right_minus_left"]
    review.require(type(delta) is dict and set(delta) == STATS and
                   all(type(delta[k]) is int for k in trend.FIELDS) and
                   type(delta["stages"]) is dict and
                   set(delta["stages"]) == set(triage.STAGES) and
                   type(delta["reasons"]) is dict and
                   set(delta["reasons"]) == set(triage.REASONS) and
                   all(type(v) is int for v in delta["stages"].values()) and
                   all(type(v) is int for v in delta["reasons"].values()) and
                   delta == trend.difference(report["left"], report["right"]),
                   "Human count deltas are not the exact native arithmetic")


def inspect(folder: Path) -> dict:
    review.require(folder.is_absolute() and not folder.is_symlink() and
                   folder.parent == folder.parent.resolve(strict=True),
                   "Recipient comparison folder must be an owner-private literal path")
    mode = folder.stat(follow_symlinks=False)
    review.require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid() and
                   mode.st_mode & 0o077 == 0 and
                   {p.name for p in folder.iterdir()} == OUTPUTS,
                   "Incomplete PRIVATE source-free comparison directory")
    manifest_raw = review.private_read(folder / "manifest.json")
    manifest = verify.json_obj(manifest_raw)
    review.require(type(manifest) is dict and set(manifest) == MANIFEST and
                   manifest.get("kind") == trend.KIND + ".local_receipt" and
                   type(manifest.get("schema_version")) is int and
                   manifest["schema_version"] == 1 and
                   manifest.get("disposition") == "UNVERIFIED_HUMAN_COUNTS_ONLY" and
                   manifest.get("warning") == trend.WARNING and
                   all(manifest.get(flag) is False for flag in review.FLAGS) and
                   manifest_raw == workspace.pretty(manifest) and
                   type(manifest.get("files")) is dict and
                   set(manifest["files"]) == OUTPUTS - {"manifest.json"},
                   "Original local comparison receipt has unexpected claims")
    payloads = {}
    for name in sorted(OUTPUTS - {"manifest.json"}):
        desc = manifest["files"][name]
        review.require(type(desc) is dict and set(desc) == {"bytes", "sha256"} and
                       type(desc["sha256"]) is str and
                       review.HEX.fullmatch(desc["sha256"]) is not None,
                       "Invalid original receipt descriptor")
        declared = read_cockpit.nonnegative(desc["bytes"], "receipt file bytes",
                                            verify.MAX_BYTES)
        raw = review.private_read(folder / name)
        review.require(len(raw) == declared and
                       hashlib.sha256(raw).hexdigest() == desc["sha256"],
                       "Original source-free recipient receipt checksum mismatch")
        payloads[name] = raw
    report = verify.json_obj(payloads["counts.json"])
    valid_report(report)
    review.require(payloads == trend.artifacts(report),
                   "HUMAN comparison page, CSV or canonical JSON diverged")
    review.require(review.private_read(folder / "manifest.json") == manifest_raw,
                   "Comparison manifest changed during reading")
    for name, raw in payloads.items():
        review.require(review.private_read(folder / name) == raw,
                       "Comparison output changed during local reading")
    return {"left_slots": report["left"]["slots"],
            "right_slots": report["right"]["slots"],
            "left_pending": report["left"]["pending"],
            "right_pending": report["right"]["pending"]}


def main() -> int:
    p = argparse.ArgumentParser(description=(
        "Read-only reopen of a private native HUMAN workload trend packet; "
        "checks local bytes and rendering, not trusted source/consent"))
    p.add_argument("--receipt", type=Path, required=True,
                   help="Complete original PRIVATE recipient trend report folder")
    args = p.parse_args()
    try:
        result = inspect(args.receipt)
        print("REVIEW_ONLY: unsigned recipient HUMAN comparison internally consistent. "
              "Left/right pending: " + str(result["left_pending"]) + "/" +
              str(result["right_pending"]) + ". Not proof of a fix.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: comparison receipt is incomplete or inconsistent; "
              "no source authentication or release.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
