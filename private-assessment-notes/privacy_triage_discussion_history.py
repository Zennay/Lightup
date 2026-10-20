#!/usr/bin/env python3
"""PRIVATE original-bound HUMAN action chronology, never a security verdict.

Reads two to eight already finalized owner-private HUMAN discussion action
packets, preserving literal stage and note-content-change distinctions without
publishing the original questions, evidence or source. Nothing is dispatched.
"""
from __future__ import annotations

import csv
from hashlib import sha256
import html
import io
import os
from pathlib import Path
import shutil
import tempfile

from notes import Hold, file_new, private_directory, private_input, save_json
from privacy_triage import FALSE_FLAGS
from privacy_triage_discussion_history_studio import render as history_studio
from privacy_triage_discussion_actions import (
    STEPS, admit_room, read_actions, reopen_actions,
)

SCHEMA = "lightup.private_notes_human_discussion_action_history.v1"
MIN_ROUNDS = 2
MAX_ROUNDS = 8
FIELDS = ("original_ordinal", "human_round", "human_step",
          "previous_human_step", "human_step_changed",
          "private_question_present", "private_question_changed")


def csv_history(rows: list[dict]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FIELDS, lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({
            key: ("TRUE" if value else "FALSE") if type(value) is bool else value
            for key, value in row.items()
        })
    return output.getvalue().encode("utf-8")


def overview(items: list[dict], selected_count: int, copies: list[list[int]]) -> bytes:
    lines = []
    for ordinal in range(1, selected_count+1):
        subset = [row for row in items if row["slot"] == ordinal]
        chronology = " → ".join(html.escape(row["step"]) for row in subset)
        steps = sum(row["stage_changed"] for row in subset)
        notes = sum(row["question_changed"] for row in subset)
        lines.append("<li><b>Selected ORIGINAL slot #" + str(ordinal) +
                     "</b>: " + chronology + " · literal HUMAN stage changes " +
                     str(steps) + " · PRIVATE question changes " + str(notes) +
                     " (text withheld)</li>")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN discussion chronology</title>
<style>body{max-width:940px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui}
aside{border-left:5px solid #a94427;background:#fff0e8;padding:1rem}
li{padding:8px;border-bottom:1px solid #ddd}a:focus-visible{outline:3px solid #b16f24}</style>
<h1>PRIVATE HUMAN discussion · manually ordered action rounds</h1>
<aside><b>DRAFT/HOLD · HUMAN ONLY · NOT A VERIFIED FIX.</b>
This is only an internal chronology of manually ordered, completed
owner-private HUMAN action packets. Fewer WITHHOLD proposals do not establish
privacy safety, remediation, client consent, verified reviewer identities,
recipient authority or release approval. Identical action bytes do not
authenticate independent reviewers or dates. Never share this private page.</aside>
<p>Selected original positions: """ + str(selected_count) +
            """. Manually supplied rounds: """ +
            str(max((x["round"] for x in items), default=0)) +
            """. Byte-identical action round pairs: """ + str(len(copies)) +
            """. Questions are withheld from this page. Unchanged labels do not
prove that original sources, targets or risks are unchanged.</p>
<ol>""" + "".join(lines) +
            """</ol><footer>No original source bytes, filenames, digests,
PRIVATE question text, reviewer identity or scanner data in this HTML.
No network, target, model, grant, messaging, dispatch, consent or release.
Full original source-bound reviewer packets remain owner-private and mandatory.
</footer></html>""").encode("utf-8")


def create(original: str, reviews: list[str], received_room: str,
           final_rooms: list[str], parent_name: str) -> int:
    if not MIN_ROUNDS <= len(final_rooms) <= MAX_ROUNDS:
        raise Hold("HOLD: choose two to eight completed PRIVATE HUMAN action rooms")
    path_ids = [str(private_directory(path).resolve()) for path in final_rooms]
    if len(set(path_ids)) != len(path_ids):
        raise Hold("HOLD: duplicate HUMAN action-room directories are forbidden")
    sources, manifest, decisions, packets, selected_raw, selected = admit_room(
        original, reviews, received_room)
    prior = None
    action_rounds = []
    summaries = []
    round_csv_sha = []
    for moment, folder in enumerate(final_rooms, 1):
        # Each exact completed source-room receipt and derived HTML is reopened
        # against the ORIGINAL complete data, never a caller-supplied claim.
        reopen_actions(original, reviews, received_room, folder)
        raw = private_input(str(Path(folder) / "PRIVATE-HUMAN-actions.csv"), 65536)
        rows = read_actions(raw, selected)
        round_csv_sha.append(sha256(raw).hexdigest())
        action_rounds.append(rows)
        for position, row in enumerate(rows, 1):
            before = prior[position-1] if prior is not None else None
            summaries.append({
                "slot": position,
                "ordinal": int(row["original_ordinal"]),
                "round": moment,
                "step": row["human_next_step"],
                "previous_step": before["human_next_step"] if before else "NONE",
                "stage_changed": (before is not None and
                                  before["human_next_step"] != row["human_next_step"]),
                "question_present": bool(row["private_human_question"]),
                "question_changed": (before is not None and
                                    before["private_human_question"] !=
                                    row["private_human_question"]),
            })
        prior = rows
    copies = [[first+1, second+1]
              for first in range(len(round_csv_sha))
              for second in range(first+1, len(round_csv_sha))
              if round_csv_sha[first] == round_csv_sha[second]]
    export = [
        {"original_ordinal": s["ordinal"], "human_round": s["round"],
         "human_step": s["step"], "previous_human_step": s["previous_step"],
         "human_step_changed": s["stage_changed"],
         "private_question_present": s["question_present"],
         "private_question_changed": s["question_changed"]}
        for s in summaries
    ]
    parent = private_directory(parent_name)
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-action-history-",
                                  dir=parent))
    os.chmod(output, 0o700)
    finished = False
    try:
        save_json(output / "PRIVATE-HUMAN-action-history-receipt.json", {
            "schema": SCHEMA, "claimed_status": "HOLD", "human_only": True,
            "original_count": len(sources), "selected_count": len(selected),
            "human_rounds": len(action_rounds),
            "selected_original_ordinals": [ordinal for ordinal, _ in selected],
            "original_manifest_sha256_unsigned": manifest,
            "original_human_csv_sha256_unsigned": decisions,
            "received_selected_csv_sha256_unsigned": sha256(selected_raw).hexdigest(),
            "original_reviewer_csv_sha256_unsigned": [
                packet["csv_sha256_unsigned"] for packet in packets],
            "manually_ordered_action_csv_sha256_unsigned": round_csv_sha,
            "identical_human_action_round_pairs": copies,
            "independent_reviewer_identities_not_verified": True,
            "human_stages_are_not_remediation_evidence": True,
            **{flag: False for flag in FALSE_FLAGS},
        })
        file_new(output / "PRIVATE-HUMAN-action-history.csv", csv_history(export))
        file_new(output / "PRIVATE-HUMAN-action-history.html",
                 overview(summaries, len(selected), copies))
        file_new(output / "PRIVATE-HUMAN-action-history-studio.html",
                 history_studio(summaries, len(selected), len(action_rounds)))
        finished = True
        print("HOLD: PRIVATE source-bound HUMAN action chronology written; NO review clearance")
        print("OPEN LOCALLY: " + str(output / "PRIVATE-HUMAN-action-history.html"))
        return 3
    finally:
        if not finished:
            shutil.rmtree(output)
