#!/usr/bin/env python3
"""Revise source-bound PRIVATE HUMAN review stages/notes into a NEW complete workroom.

Original source workrooms, original HUMAN journals and their workspaces are NEVER
edited in place. No target contact, live scans, grants, security verdicts or Apply.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys

import prepare
import read_cockpit
import verify
import workroom_actions

review = verify.review
triage = verify.triage
workspace = verify.workspace

KIND = "lightup.private_human_offline_revision_plan"
WARNING = ("Local source-owner HUMAN notes only. A stage is NOT proof of an "
           "authenticated reviewer, consent, accepted finding, retest, fix or release.")
HEAD = {"kind", "schema_version", "disposition", "source_sessions", "changes", "warning"}
BINDING = {"slot", "session_sha256"}
CHANGE = {"slot", "ordinal", "stage", "note_action", "human_note"}

def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def private_workroom(path: Path) -> tuple[list[Path], list[dict[str, bytes]]]:
    review.require(path.is_absolute() and not path.is_symlink() and
                   path.parent == path.parent.resolve(strict=True),
                   "Workroom must be a literal absolute PRIVATE location")
    mode = path.stat(follow_symlinks=False)
    review.require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid() and
                   mode.st_mode & 0o077 == 0, "Workroom is not owner-only 0700")
    names = {entry.name for entry in path.iterdir()}
    originals = [path / f"original-{i:02}" for i in range(1, 13)
                 if f"original-{i:02}" in names]
    review.require(originals and names ==
                   {"index.html", "tasks.html", "cockpit"} |
                   {item.name for item in originals} and
                   originals == [path / f"original-{i:02}"
                                 for i in range(1, len(originals) + 1)],
                   "Incomplete or extraneous PRIVATE original owner workroom entries")
    review.require(review.private_read(path / "index.html") ==
                   prepare.local_home(len(originals)),
                   "Original workroom navigator changed")
    source_payloads = []
    for folder in originals:
        _, originals_raw = verify.inspect(folder)
        source_payloads.append({
            **originals_raw,
            "manifest.json": review.private_read(folder / "manifest.json"),
        })
    status = read_cockpit.inspect(path / "cockpit")
    review.require(status["original_source_slots_not_unique_cases"] == len(originals),
                   "PRIVATE cockpit source count differs from original workroom")
    source_only = [x for x in source_payloads]
    action_payloads = workroom_actions.collect(originals)
    review.require(review.private_read(path / "tasks.html") ==
                   workroom_actions.render(action_payloads),
                   "Original workroom HUMAN task page differs from native source")
    # Baseline source bytes are pinned for the complete preparation. A later
    # change causes a full HOLD before the new private workroom is published.
    return originals, source_only

def proposal(raw: list[dict[str, bytes]]) -> dict:
    return {"kind": KIND, "schema_version": 1,
            "disposition": "ORIGINAL_PRIVATE_HUMAN_NOTES_ONLY",
            "source_sessions": [
                {"slot": idx, "session_sha256": digest(files["session.json"])}
                for idx, files in enumerate(raw, 1)],
            "changes": [], "warning": WARNING}

def accept(plan: dict, sources: list[dict[str, bytes]]) -> list[dict]:
    review.require(type(plan) is dict and set(plan) == HEAD and
                   plan["kind"] == KIND and
                   type(plan["schema_version"]) is int and plan["schema_version"] == 1 and
                   plan["disposition"] == "ORIGINAL_PRIVATE_HUMAN_NOTES_ONLY" and
                   plan["warning"] == WARNING,
                   "Unknown or modified PRIVATE HUMAN revision plan")
    refs = plan["source_sessions"]
    review.require(type(refs) is list and len(refs) == len(sources),
                   "Incomplete source-bound original HUMAN session bindings")
    for idx, (item, raw) in enumerate(zip(refs, sources), 1):
        review.require(type(item) is dict and set(item) == BINDING and
                       type(item["slot"]) is int and item["slot"] == idx and
                       type(item["session_sha256"]) is str and
                       item["session_sha256"] == digest(raw["session.json"]),
                       "Stale or changed original HUMAN workroom session; make a new plan")
    changes = plan["changes"]
    review.require(type(changes) is list and 1 <= len(changes) <= 64,
                   "Require 1–64 explicit original HUMAN edits")
    seen = set()
    for item in changes:
        review.require(type(item) is dict and set(item) == CHANGE,
                       "Unknown PRIVATE HUMAN edit shape")
        slot = item["slot"]
        ordinal = item["ordinal"]
        review.require(type(slot) is int and 1 <= slot <= len(sources) and
                       type(ordinal) is int and ordinal >= 1,
                       "Invalid original source slot or question ordinal")
        review.require((slot, ordinal) not in seen, "Duplicate original HUMAN edit")
        seen.add((slot, ordinal))
        review.require(type(item["stage"]) is str and item["stage"] in triage.STAGES,
                       "Original HUMAN stage unknown")
        review.require(type(item["note_action"]) is str and
                       item["note_action"] in {"keep", "replace", "clear"},
                       "PRIVATE note operation must be keep, replace or clear")
        review.exact_string(item["human_note"], 1200, "PRIVATE HUMAN note")
        review.require(item["note_action"] == "replace" or item["human_note"] == "",
                       "PRIVATE note text can only be present on replace action")
    return changes

def recheck(source_path: Path, originals: list[Path],
            snapshots: list[dict[str, bytes]], navigator: bytes,
            task_page: bytes, receiver: dict) -> None:
    review.require(review.private_read(source_path / "index.html") == navigator and
                   review.private_read(source_path / "tasks.html") == task_page,
                   "Original owner-private navigator or HUMAN tasks changed")
    review.require(read_cockpit.inspect(source_path / "cockpit") == receiver,
                   "Original source-free cockpit changed before revision publication")
    review.require({p.name for p in source_path.iterdir()} ==
                   {"index.html", "tasks.html", "cockpit"} |
                   {p.name for p in originals}, "Original workroom membership changed")
    for folder, original in zip(originals, snapshots):
        _, now = verify.inspect(folder)
        review.require({**now, "manifest.json": review.private_read(folder / "manifest.json")} ==
                       original, "Original source or HUMAN journal changed during revision")

def revise(source_path: Path, plan_path: Path, destination: Path) -> dict:
    originals, snapshots = private_workroom(source_path)
    review.require(destination.is_absolute() and
                   destination.parent == destination.parent.resolve(strict=True) and
                   destination != source_path and
                   source_path not in destination.parents and
                   destination not in source_path.parents and
                   not destination.exists() and not destination.is_symlink(),
                   "New revision must be a fresh PRIVATE sibling, never original")
    triage.private_parent(destination)
    navigator = review.private_read(source_path / "index.html")
    task_page = review.private_read(source_path / "tasks.html")
    receiver = read_cockpit.inspect(source_path / "cockpit")
    plan = verify.json_obj(review.private_read(plan_path))
    edits = accept(plan, snapshots)
    sessions = []
    for source in snapshots:
        current = source["current.json"]
        previous = source.get("previous.json")
        packet = review.parse_packet_data(current)
        prior = review.parse_packet_data(previous) if previous is not None else None
        session = triage.admit_session(source["session.json"],
                                     triage.make_session(packet, prior, current, previous))
        sessions.append(session)
    for item in edits:
        row = sessions[item["slot"] - 1]["records"]
        review.require(item["ordinal"] <= len(row), "Original HUMAN ordinal not found")
        rec = row[item["ordinal"] - 1]
        prior_note = rec["human_note"]
        next_note = (prior_note if item["note_action"] == "keep" else
                     item["human_note"] if item["note_action"] == "replace" else "")
        review.require(item["stage"] != rec["stage"] or next_note != prior_note,
                       "No actual local HUMAN change requested")
        rec["stage"] = item["stage"]
        rec["human_note"] = next_note
        rec["updated_utc"] = triage.now_utc()
    stage = destination.parent / (".lightup-private-revise-" + secrets.token_hex(12))
    os.mkdir(stage, mode=0o700)
    try:
        raw_dirs = []
        for index, source in enumerate(snapshots, 1):
            parent = stage / f"raw-{index:02}"
            os.mkdir(parent, mode=0o700)
            private = {
                "current.json": source["current.json"],
                "session.json": triage.canonical(sessions[index - 1]),
            }
            if "previous.json" in source:
                private["previous.json"] = source["previous.json"]
            for name, raw in private.items():
                review.private_publish(parent / name, raw)
            raw_dirs.append(parent)
        def before_publish() -> None:
            recheck(source_path, originals, snapshots, navigator, task_page, receiver)
            review.require(review.private_read(plan_path) == workspace.pretty(plan) or
                           verify.json_obj(review.private_read(plan_path)) == plan,
                           "PRIVATE HUMAN edit plan changed before publication")
        output = prepare.publish(raw_dirs, destination, before_publish=before_publish)
        return {"changes": len(edits), "original_slots": len(snapshots),
                "locally_pending_not_fixes": output["human_pending"]}
    finally:
        shutil.rmtree(stage)

def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Draft and apply original-source-bound PRIVATE HUMAN stage/note revisions "
        "as a new complete offline workroom; old workroom never edited"))
    parser.add_argument("--workroom", type=Path, required=True,
                        help="Previously admitted original PRIVATE workroom")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--draft-plan", type=Path, help="Create new owner-only PRIVATE JSON edit plan")
    mode.add_argument("--plan", type=Path, help="Existing edited private JSON plan")
    parser.add_argument("--output-dir", type=Path,
                        help="New complete owner-private workroom, required with --plan")
    args = parser.parse_args()
    try:
        if args.draft_plan:
            review.require(args.output_dir is None and
                           args.draft_plan.parent != args.workroom and
                           args.workroom not in args.draft_plan.parents,
                           "PRIVATE revision plan must be outside original workroom")
            triage.private_parent(args.draft_plan)
            _, snapshots = private_workroom(args.workroom)
            review.private_publish(args.draft_plan, workspace.pretty(proposal(snapshots)))
            print("PRIVATE original-session-bound HUMAN edit plan created.")
            print("Edit only changes[] and keep source_sessions[] hashes unchanged.")
        else:
            review.require(args.output_dir is not None, "New PRIVATE output directory required")
            summary = revise(args.workroom, args.plan, args.output_dir)
            print("NEW PRIVATE HUMAN workroom published; original untouched.")
            print("Edited " + str(summary["changes"]) + " source-bound HUMAN record(s) across " +
                  str(summary["original_slots"]) + " slots; " +
                  str(summary["locally_pending_not_fixes"]) + " still locally pending.")
        print("REVIEW_ONLY: no authenticated authorization, original fix, grant, scan or retest.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: original PRIVATE HUMAN revision could not be completed.", file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
