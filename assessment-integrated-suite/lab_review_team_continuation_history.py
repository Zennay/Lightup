#!/usr/bin/env python3
"""One offline original-source HUMAN chronology of a saved batch and continuations.

Compares operator-ordered proposals, not real timestamps, consent, findings or
security verification. Native original source and each PRIVATE lineage round
are re-admitted before a NEW 0700/0600 owner-only history is published.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
from pathlib import Path
import shutil
import sys

import lab_plans
import lab_plan_review
import lab_review_history
import lab_review_team_batch_history as base_history
import lab_review_team_batch_reopen as batch_reopen
import lab_review_team_continue_reopen as continued_reopen
import private_session as privacy
import route_queue
import workpack_progress

SCHEMA = "lightup.private.original-lab-human-continuation-history.v1"
MAX_CONTINUATIONS = 7


def _csv(rows: list[dict], fields: tuple[str, ...]) -> bytes:
    data = io.StringIO(newline="")
    writer = csv.writer(data, lineterminator="\r\n")
    writer.writerow(fields)
    for item in rows:
        writer.writerow([item[key] for key in fields])
    return data.getvalue().encode("utf-8")


def build(packets: list[str], final_room: str, handoff_room: str,
          root_batch: str, continuation_rooms: list[str],
          parent: str, folder: str) -> Path:
    if (type(continuation_rooms) is not list
            or not 1 <= len(continuation_rooms) <= MAX_CONTINUATIONS
            or any(type(name) is not str for name in continuation_rooms)):
        raise privacy.Hold("HOLD: 1–7 source-bound HUMAN continuation rooms required")
    dest = lab_plans._new_path(parent, folder)
    root = lab_plans._packet(root_batch)
    rounds = [lab_plans._packet(name) for name in continuation_rooms]
    source_dirs = [root, *rounds, lab_plans._packet(final_room),
                   lab_plans._packet(handoff_room)]
    if (len(set([root, *rounds])) != len(rounds) + 1
            or any(path == dest or path in dest.parents for path in source_dirs)):
        raise privacy.Hold("HOLD: original HUMAN source rooms repeated or nested")
    # Each original continuation is its own full native and byte-bound
    # admission. A missing predecessor is HOLD, not a created new round.
    batch_reopen.inspect(packets, final_room, handoff_room, root_batch)
    originals, fingerprint = lab_plan_review._source_rows(packets)
    original_final = lab_review_history._admit_final(
        final_room, originals, fingerprint)
    original_team_sizes = {
        row["human_team"]: sum(item["human_team"] == row["human_team"]
                               for item in original_final)
        for row in original_final if row["human_team"]
    }
    root_rows = lab_plan_review._rows_admit(
        originals, str(root / "PRIVATE-HUMAN-CANDIDATE.csv"))
    root_receipt = workpack_progress._private_receipt(
        root / "PRIVATE-HUMAN-MULTITEAM-RECEIPT.json")
    if root_receipt["original_source_snapshot_sha256_unsigned"] != fingerprint:
        raise privacy.Hold("HOLD: original root HUMAN batch source differs")
    rosters = [[*root_receipt["teams"], *[
        {"team": item["team"], "assigned": item["assigned"],
         "disposition": "NOT_RETURNED"}
        for item in root_receipt["unreturned_original_teams"]
    ]]]
    snapshots = [root_rows]
    for index, room in enumerate(rounds):
        continued_reopen.inspect(
            packets, final_room, handoff_room, root_batch, str(room),
            prior_continuations=tuple(str(x) for x in rounds[:index]))
        data = lab_plan_review._rows_admit(
            originals, str(room / "PRIVATE-HUMAN-CONTINUED-CANDIDATE.csv"))
        receipt = workpack_progress._private_receipt(
            room / "PRIVATE-HUMAN-CONTINUATION-RECEIPT.json")
        if receipt["original_source_fingerprint_sha256_unsigned"] != fingerprint:
            raise privacy.Hold("HOLD: source identity changed across PRIVATE HUMAN rounds")
        roster = [*receipt["team_outcomes"], *[
            {"team": name, "assigned": original_team_sizes.get(name, 0),
             "disposition": "NOT_RETURNED"}
            for name in receipt["not_returned_team_names"]
        ]]
        snapshots.append(data)
        rosters.append(roster)

    changes, transitions = [], []
    for i, (left, right) in enumerate(zip(snapshots, snapshots[1:]), start=1):
        for prior, updated in zip(left, right):
            if (prior["human_stage"] != updated["human_stage"] or
                    prior["human_question"] != updated["human_question"]):
                changes.append({
                    "previous_position": i, "current_position": i + 1,
                    "proposal_slot": int(updated["proposal_slot"]),
                    "team": updated["human_team"] or "Unassigned",
                    "before_stage": prior["human_stage"],
                    "after_stage": updated["human_stage"],
                    "private_question_changed": (
                        prior["human_question"] != updated["human_question"]),
                })
        a = {row["team"]: row["disposition"] for row in rosters[i - 1]}
        b = {row["team"]: row["disposition"] for row in rosters[i]}
        for name in sorted(set(a) | set(b)):
            before, after = a.get(name, "NOT_RETURNED"), b.get(name, "NOT_RETURNED")
            if before != after:
                transitions.append({
                    "previous_position": i, "current_position": i + 1,
                    "team": name, "previous_disposition": before,
                    "current_disposition": after,
                })

    # Reuse the original source-free scriptless private HUMAN page from the
    # already-integrated history product, without changing source-owner code.
    summary = {
        "schema": SCHEMA, "status": "REVIEW_ONLY", "authority": privacy.AUTHORITY,
        "source_verified": False, "consent_verified": False,
        "reviewer_authenticated": False, "operator_authenticated": False,
        "human_go_recorded": False, "scan_or_release_allowed": False,
        "real_chronology_verified": False, "private_question_text_included": False,
        "original_urls_or_paths_included": False,
        "operator_supplied_rounds": len(snapshots),
        "changed_original_proposals": changes,
        "human_team_transitions": transitions,
        "human_stage_counts": [{
            "operator_position": index,
            "stages": {stage: sum(row["human_stage"] == stage for row in snapshot)
                       for stage in route_queue.STAGES}
        } for index, snapshot in enumerate(snapshots, start=1)],
    }
    artifacts = (
        ("OPEN-PRIVATE.html", base_history._page(
            snapshots, rosters, changes, transitions)),
        ("PRIVATE-HUMAN-CONTINUATION-HISTORY.json",
         (json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")),
        ("PRIVATE-HUMAN-CONTINUATION-CHANGES.csv",
         _csv(changes, ("previous_position", "current_position", "proposal_slot",
                        "team", "before_stage", "after_stage", "private_question_changed"))),
        ("PRIVATE-HUMAN-CONTINUATION-TEAM-TRANSITIONS.csv",
         _csv(transitions, ("previous_position", "current_position", "team",
                            "previous_disposition", "current_disposition"))),
    )
    dest.mkdir(mode=0o700)
    try:
        if not privacy.private(dest, True):
            raise privacy.Hold("HOLD: new owner-private HUMAN history custody invalid")
        for filename, payload in artifacts:
            privacy.private_write(dest, filename, payload)
        directory_fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        shutil.rmtree(dest)
        raise privacy.Hold("HOLD: original HUMAN chain history not published") from None
    return dest / "OPEN-PRIVATE.html"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE HUMAN proposal timeline from 1 root + 1–7 continuations")
    parser.add_argument("--packet", action="append", required=True)
    parser.add_argument("--final-room", required=True)
    parser.add_argument("--handoff-room", required=True)
    parser.add_argument("--root-batch", required=True)
    parser.add_argument("--continuation-room", action="append", required=True)
    parser.add_argument("--private-parent", required=True)
    parser.add_argument("--folder", required=True)
    parser.add_argument("--human-confirm", required=True)
    args = parser.parse_args(argv)
    try:
        if args.human_confirm != "BUILD ORIGINAL PRIVATE HUMAN CONTINUATION HISTORY":
            raise privacy.Hold("HOLD: manual original HUMAN chronology confirmation missing")
        result = build(args.packet, args.final_room, args.handoff_room,
                       args.root_batch, args.continuation_room,
                       args.private_parent, args.folder)
        print("PRIVATE REVIEW_ONLY: original HUMAN Lab continuation history prepared")
        print("OPEN LOCALLY: " + str(result))
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc, privacy.Hold) else
              "HOLD: original source-bound HUMAN continuation history refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
