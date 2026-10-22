#!/usr/bin/env python3
"""Publish ONLY the canonical source-free PRIVATE cockpit for a separate operator.

Copies a strictly enumerated anonymous-human workload artifact, not the
containing original workroom or any original source, HUMAN note, fingerprint,
customer label, underlying material, grant, scan task or authorized request.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

import read_cockpit
import verify

review = verify.review
workspace = verify.workspace
triage = verify.triage

def prepare(workroom: Path, output: Path) -> dict:
    review.require(workroom.is_absolute() and workroom.parent ==
                   workroom.parent.resolve(strict=True) and not workroom.is_symlink(),
                   "Only literal owner-private original workrooms accepted")
    mode = workroom.stat(follow_symlinks=False)
    review.require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid() and
                   mode.st_mode & 0o077 == 0,
                   "Original source-owner workroom must be an owner-only 0700 folder")
    cockpit = workroom / "cockpit"
    review.require(cockpit.parent == workroom and
                   output.is_absolute() and output.parent == output.parent.resolve(strict=True) and
                   output != workroom and output != cockpit and
                   workroom not in output.parents and output not in workroom.parents and
                   not output.exists() and not output.is_symlink(),
                   "Recipient export cannot be an original source/workroom path")
    triage.private_parent(output)

    # Incoming complete source-free product acceptance is required before any
    # copying. The output shall have EXACTLY the source-free whitelisted filenames.
    admitted = read_cockpit.inspect(cockpit)
    manifest_bytes = review.private_read(cockpit / "manifest.json")
    manifest = verify.json_obj(manifest_bytes)
    names = (read_cockpit.DEFAULT |
             (read_cockpit.HISTORY if admitted["same_original_source_claimed"] else frozenset()))
    review.require(set(manifest["files"]) == names and
                   {p.name for p in cockpit.iterdir()} == set(names) | {"manifest.json"},
                   "Source-free recipient inventory is not exact")
    payloads = {name: review.private_read(cockpit / name) for name in sorted(names)}

    # A symlink, injected file, a post-admission replacement or extra original
    # material in the private cockpit cannot be transferred by this utility.
    again = read_cockpit.inspect(cockpit)
    review.require(again == admitted and
                   review.private_read(cockpit / "manifest.json") == manifest_bytes and
                   {p.name for p in cockpit.iterdir()} == set(names) | {"manifest.json"},
                   "Source-free cockpit changed during recipient preparation")
    for name, value in payloads.items():
        review.require(review.private_read(cockpit / name) == value,
                       "PRIVATE source-free summary changed during transfer")

    # Original owner implementation: private fresh 0700 folder, fsynced 0600
    # regular files, exclusive Linux atomic publication. No archive, network,
    # auto-upload or weakening of the existing local private access boundary.
    workspace.publish_bundle(output, payloads, manifest_bytes)
    return {"human_slots": admitted["original_source_slots_not_unique_cases"],
            "locally_pending_not_fixes": admitted["local_pending_human_questions_not_fixes"],
            "only_source_free_files": len(payloads) + 1,
            "history": admitted["same_original_source_claimed"]}

def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Atomically prepare a private receiving operator's canonical source-free "
        "cockpit folder without copying original human/evidence source folders"))
    parser.add_argument("--workroom", type=Path, required=True,
                        help="Previously published original source-owner PRIVATE workroom")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="NEW recipient folder under existing PRIVATE 0700 parent")
    args = parser.parse_args()
    try:
        result = prepare(args.workroom, args.output_dir)
        print("PRIVATE SOURCE-FREE HUMAN handoff folder published atomically.")
        print("Contains ONLY " + str(result["only_source_free_files"]) +
              " source-free cockpit files; " + str(result["human_slots"]) +
              " original workroom slot(s); " +
              str(result["locally_pending_not_fixes"]) +
              " locally pending HUMAN questions. No original source/HUMAN note bytes transferred.")
        print("Receiving operator should run read_cockpit.py --cockpit /ABSOLUTE/RECEIVED/FOLDER")
        print("HUMAN ONLY: no cryptographic sender authenticity, client consent or security approval.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: PRIVATE recipient handoff could not be admitted; nothing authorized.",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
