#!/usr/bin/env python3
"""Independently reopen one native PRIVATE HUMAN recipient follow-up directory.

Internal-consistency check only; never asserts that absent original client
sources, original consent, actual evidence or remediation were authenticated.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

import recipient_journal as journal

review = journal.review
workspace = journal.workspace
verify = journal.verify
recipient_studio = journal.recipient_studio
read_cockpit = recipient_studio.trend.read_cockpit
triage = journal.triage

OUTPUTS = frozenset(("journal.json", "private-review.html",
                     "anonymous-counts.json", "manifest.json"))
MANIFEST = frozenset(("kind", "schema_version", "disposition",
                      "warning", "files", *review.FLAGS))


def original_local_journal(doc: object) -> dict:
    """Admit stored HUMAN groups without pretending to know missing source facts."""
    review.require(type(doc) is dict and set(doc) == journal.JOURNAL_KEYS and
                   doc.get("kind") == recipient_studio.JOURNAL_KIND and
                   type(doc.get("schema_version")) is int and
                   doc["schema_version"] == 1 and
                   doc.get("disposition") == recipient_studio.DISPOSITION and
                   doc.get("warning") == recipient_studio.WARNING and
                   type(doc.get("source_sha256")) is str and
                   review.HEX.fullmatch(doc["source_sha256"]) is not None,
                   "Unrecognized original unsigned HUMAN review journal")
    rows = doc.get("entries")
    expected = sorted(triage.REASONS)
    review.require(type(rows) is list and len(rows) == len(expected),
                   "Incomplete native original HUMAN reason list")
    for key, row in zip(expected, rows):
        review.require(type(row) is dict and set(row) == journal.ENTRY_KEYS and
                       type(row.get("reason")) is str and row["reason"] == key and
                       type(row.get("count")) is int and
                       0 <= row["count"] <= 100000 and
                       type(row.get("delta")) is int and
                       -100000 <= row["delta"] <= 100000 and
                       type(row.get("stage")) is str and row["stage"] in journal.STAGES and
                       type(row.get("route")) is str and row["route"] in journal.ROUTES,
                       "Unsafe original HUMAN row/category/delta")
        journal.private_note(row["note"])
    return doc


def inspect(folder: Path) -> dict:
    review.require(folder.is_absolute() and not folder.is_symlink() and
                   folder.parent == folder.parent.resolve(strict=True),
                   "Private local HUMAN handoff must be literal owner directory")
    meta = folder.stat(follow_symlinks=False)
    review.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid() and
                   meta.st_mode & 0o077 == 0 and
                   {item.name for item in folder.iterdir()} == OUTPUTS,
                   "Incomplete or shared private HUMAN follow-up inventory")
    manifest_raw = review.private_read(folder / "manifest.json")
    m = verify.json_obj(manifest_raw)
    review.require(type(m) is dict and set(m) == MANIFEST and
                   m.get("kind") == journal.FOLLOWUP_KIND + ".local_receipt" and
                   type(m.get("schema_version")) is int and m["schema_version"] == 1 and
                   m.get("disposition") == recipient_studio.DISPOSITION and
                   m.get("warning") == recipient_studio.WARNING and
                   all(m.get(flag) is False for flag in review.FLAGS) and
                   type(m.get("files")) is dict and
                   set(m["files"]) == OUTPUTS - {"manifest.json"} and
                   manifest_raw == workspace.pretty(m),
                   "Invalid native unsigned local HUMAN handoff manifest")
    original = {}
    for filename in sorted(OUTPUTS - {"manifest.json"}):
        desc = m["files"][filename]
        review.require(type(desc) is dict and
                       set(desc) == {"bytes","sha256"} and
                       type(desc.get("sha256")) is str and
                       review.HEX.fullmatch(desc["sha256"]) is not None,
                       "Invalid or noncanonical PRIVATE HUMAN file fingerprint")
        n = read_cockpit.nonnegative(desc.get("bytes"),
                                    "native HUMAN follow-up file", verify.MAX_BYTES)
        content = review.private_read(folder / filename)
        review.require(len(content) == n and
                       hashlib.sha256(content).hexdigest() == desc["sha256"],
                       "PRIVATE local HUMAN follow-up content changed")
        original[filename] = content
    doc = original_local_journal(verify.json_obj(original["journal.json"]))
    review.require(original == journal.artifacts(doc),
                   "Native PRIVATE HUMAN HTML/JSON was not faithfully reproduced")
    review.require(review.private_read(folder / "manifest.json") == manifest_raw,
                   "HUMAN follow-up receipt changed during native local admission")
    for name, content in original.items():
        review.require(review.private_read(folder / name) == content,
                       "HUMAN report file changed during native local admission")
    return {"human_reason_groups": len(doc["entries"]),
            "open_human_reason_groups": sum(row["stage"] != "answered_human"
                                            for row in doc["entries"]),
            "files": len(OUTPUTS)}


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Reopen original native PRIVATE HUMAN recipient follow-up "
        "without source data; only local integrity, never source provenance"))
    parser.add_argument("--folder", type=Path, required=True,
                        help="Complete private 0700 native HUMAN workroom directory")
    args = parser.parse_args()
    try:
        result = inspect(args.folder)
        print("REVIEW_ONLY: native PRIVATE HUMAN follow-up is locally consistent, " +
              str(result["human_reason_groups"]) + " aggregate reason groups. "
              "Original source provenance/consent/retest NOT authenticated.")
        return 2
    except (review.Hold, OSError, ValueError, UnicodeError):
        print("HOLD: private HUMAN follow-up incomplete or altered. No authorization.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
