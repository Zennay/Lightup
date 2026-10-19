#!/usr/bin/env python3
"""Quick private HUMAN review amendment: one chosen original question, new workroom.

Sensitive HUMAN note contents are read from a pre-existing 0600 input file,
never supplied in argv and never put into the anonymous recipient cockpit.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shutil
import sys

import revise

review = revise.review
triage = revise.triage
workspace = revise.workspace

def change_one(workroom: Path, output: Path, slot: int, ordinal: int,
               stage: str | None, note_path: Path | None, clear: bool) -> dict:
    _, snapshots = revise.private_workroom(workroom)
    review.require(type(slot) is int and 1 <= slot <= len(snapshots) and
                   type(ordinal) is int and ordinal > 0,
                   "Original HUMAN source slot/ordinal invalid")
    source = snapshots[slot - 1]
    current = source["current.json"]
    previous = source.get("previous.json")
    now = revise.verify.review.parse_packet_data(current)
    old = (revise.verify.review.parse_packet_data(previous)
           if previous is not None else None)
    human = triage.admit_session(
        source["session.json"],
        triage.make_session(now, old, current, previous))
    review.require(ordinal <= len(human["records"]), "Original HUMAN row not found")
    record = human["records"][ordinal - 1]
    goal = stage if stage is not None else record["stage"]
    review.require(goal in triage.STAGES, "Unknown original HUMAN review stage")
    action = "keep"
    note = ""
    if note_path is not None:
        note = review.private_read(note_path).decode("utf-8")
        note = note.removesuffix("\n").removesuffix("\r")
        review.exact_string(note, 1200, "PRIVATE original HUMAN note")
        action = "replace"
    elif clear:
        action = "clear"
    review.require(goal != record["stage"] or
                   (action == "replace" and note != record["human_note"]) or
                   (action == "clear" and bool(record["human_note"])),
                   "No concrete original HUMAN change requested")
    # A locally generated single-action plan is still bound to ALL original
    # local HUMAN session bytes and admitted by the standard batch revision path.
    plan = revise.proposal(snapshots)
    plan["changes"] = [{
        "slot": slot, "ordinal": ordinal, "stage": goal,
        "note_action": action, "human_note": note,
    }]
    review.require(output.is_absolute() and output.parent == output.parent.resolve(strict=True)
                   and not output.exists() and not output.is_symlink(),
                   "Destination is not an unused literal PRIVATE path")
    parent = triage.private_parent(output)
    staging = parent / (".lightup-private-human-amend-" + secrets.token_hex(12))
    os.mkdir(staging, mode=0o700)
    try:
        newplan = staging / "human-plan.json"
        review.private_publish(newplan, workspace.pretty(plan))
        return revise.revise(workroom, newplan, output)
    finally:
        shutil.rmtree(staging)

def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Change one existing source-bound HUMAN stage/PRIVATE note and atomically "
        "publish a NEW full evidence workroom without a manually edited JSON plan"))
    parser.add_argument("--workroom", type=Path, required=True,
                        help="Existing fully admitted owner-private source workroom")
    parser.add_argument("--slot", type=int, required=True,
                        help="Original-XX source slot shown in PRIVATE tasks.html")
    parser.add_argument("--ordinal", type=int, required=True,
                        help="Original source HUMAN question ordinal")
    parser.add_argument("--stage", choices=triage.STAGES, help="New HUMAN stage; omit to keep")
    notes = parser.add_mutually_exclusive_group()
    notes.add_argument("--note-file", type=Path, help="PRIVATE 0600 note text; not CLI text")
    notes.add_argument("--clear-note", action="store_true",
                       help="Clear this question's note in NEW version only")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Unused PRIVATE destination for an entire NEW original workroom")
    args = parser.parse_args()
    try:
        result = change_one(args.workroom, args.output_dir, args.slot, args.ordinal,
                            args.stage, args.note_file, args.clear_note)
        print("ONE original HUMAN record updated in a NEW complete owner-private workroom.")
        print("Original workroom unchanged; " + str(result["locally_pending_not_fixes"]) +
              " HUMAN question(s) remain locally pending, not verified findings.")
        print("HUMAN ONLY: no consent, grant, scan, security approval, fix or retest.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: original PRIVATE HUMAN amendment was not completed.", file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
