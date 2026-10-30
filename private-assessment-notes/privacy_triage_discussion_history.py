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
import json
import os
from pathlib import Path
import shutil
import tempfile

from notes import Hold, file_new, private_directory, private_input, save_json
from privacy_triage import FALSE_FLAGS
from privacy_triage_discussion_history_studio import render as history_studio
from privacy_triage_discussion_focus import focus_rows, csv_bytes as focus_csv, page as focus_page
from privacy_triage_discussion_actions import (
    studio as action_editor, rows_csv as action_csv, blank_rows,
    receipt as action_receipt,
)
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


def overview(items: list[dict], selected_count: int, copies: list[list[int]],
             legacy_slots: bool = False) -> bytes:
    lines = []
    # The manual selection may be sparse, e.g. ORIGINAL #2 and #9.
    # Display the actual source ordinal, never the selected-row index.
    ordinals = [row["ordinal"] for row in items if row["round"] == 1]
    for original_ordinal in ordinals:
        subset = [row for row in items if row["ordinal"] == original_ordinal]
        chronology = " → ".join(html.escape(row["step"]) for row in subset)
        steps = sum(row["stage_changed"] for row in subset)
        notes = sum(row["question_changed"] for row in subset)
        display = ("Selected ORIGINAL slot #" + str(len(lines) + 1)
                   if legacy_slots else "Original source #" + str(original_ordinal))
        lines.append("<li><b>" + display +
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


def source_state(original: str, reviews: list[str], received_room: str,
                 final_rooms: list[str]):
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
    return (sources, manifest, decisions, packets, selected_raw, selected, action_rounds, summaries, round_csv_sha, copies, export)


def history_receipt(sources, manifest, decisions, packets, selected_raw,
                    selected, action_rounds, round_csv_sha, copies) -> dict:
    return {
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
        "blank_next_human_round_original_bound": True,
        "latest_human_focus_original_bound": True,
        **{flag: False for flag in FALSE_FLAGS},
    }


def create(original: str, reviews: list[str], received_room: str,
           final_rooms: list[str], parent_name: str) -> int:
    (sources, manifest, decisions, packets, selected_raw, selected, action_rounds, summaries, round_csv_sha, copies, export) = source_state(original, reviews, received_room, final_rooms)
    parent = private_directory(parent_name)
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-action-history-",
                                  dir=parent))
    os.chmod(output, 0o700)
    finished = False
    try:
        save_json(output / "PRIVATE-HUMAN-action-history-receipt.json",
                  history_receipt(sources, manifest, decisions, packets,
                                  selected_raw, selected, action_rounds,
                                  round_csv_sha, copies))
        file_new(output / "PRIVATE-HUMAN-action-history.csv", csv_history(export))
        file_new(output / "PRIVATE-HUMAN-action-history.html",
                 overview(summaries, len(selected), copies))
        file_new(output / "PRIVATE-HUMAN-action-history-studio.html",
                 history_studio(summaries, len(selected), len(action_rounds)))
        attention = focus_rows(summaries, [x[0] for x in selected], len(action_rounds))
        file_new(output / "PRIVATE-HUMAN-latest-focus.csv", focus_csv(attention))
        file_new(output / "PRIVATE-HUMAN-latest-focus.html",
                 focus_page(attention, len(action_rounds)))
        # Next round starts explicitly EMPTY/PENDING, not adopted from
        # earlier HUMAN submissions. Original action-finalize independently
        # checks these native source bytes when this room is used as draft.
        save_json(output / "PRIVATE-HUMAN-action-source.json",
                  action_receipt(sources, manifest, decisions, packets,
                                 selected_raw, selected))
        file_new(output / "PRIVATE-HUMAN-action-template.csv",
                 action_csv(blank_rows(selected)))
        file_new(output / "PRIVATE-HUMAN-action-editor.html",
                 action_editor(selected))
        finished = True
        print("HOLD: PRIVATE source-bound HUMAN action chronology written; NO review clearance")
        print("OPEN LOCALLY: " + str(output / "PRIVATE-HUMAN-action-history.html"))
        print("LATEST HUMAN ATTENTION: " +
              str(output / "PRIVATE-HUMAN-latest-focus.html"))
        print("NEXT HUMAN ROUND (blank): " +
              str(output / "PRIVATE-HUMAN-action-editor.html"))
        return 3
    finally:
        if not finished:
            shutil.rmtree(output)



def reopen_history(original: str, reviews: list[str], received_room: str,
                   final_rooms: list[str], history_room: str) -> int:
    """Read-only exact-original history re-admission, no new output."""
    (sources, manifest, decisions, packets, selected_raw, selected,
     action_rounds, summaries, round_csv_sha, copies, export) = source_state(
        original, reviews, received_room, final_rooms)
    room = private_directory(history_room)
    binding = history_receipt(sources, manifest, decisions, packets,
                              selected_raw, selected, action_rounds,
                              round_csv_sha, copies)
    original_receipt = (
        json.dumps(binding, indent=2, sort_keys=True, ensure_ascii=False)
        + "\n").encode("utf-8")
    action_binding = action_receipt(
        sources, manifest, decisions, packets, selected_raw, selected)
    next_original_receipt = (
        json.dumps(action_binding, indent=2, sort_keys=True,
                   ensure_ascii=False) + "\n").encode("utf-8")
    actual_receipt = private_input(
        str(room / "PRIVATE-HUMAN-action-history-receipt.json"), 65536)
    previous_binding = dict(binding)
    previous_binding.pop("latest_human_focus_original_bound")
    oldest_binding = dict(previous_binding)
    oldest_binding.pop("blank_next_human_round_original_bound")
    def receipt_bytes(value):
        return (json.dumps(value, indent=2, sort_keys=True,
                           ensure_ascii=False) + "\n").encode("utf-8")

    full_next_files = (
        ("PRIVATE-HUMAN-action-source.json", next_original_receipt),
        ("PRIVATE-HUMAN-action-template.csv", action_csv(blank_rows(selected))),
        ("PRIVATE-HUMAN-action-editor.html", action_editor(selected)),
    )
    focus = focus_rows(summaries, [x[0] for x in selected], len(action_rounds))
    latest_files = (
        ("PRIVATE-HUMAN-latest-focus.csv", focus_csv(focus)),
        ("PRIVATE-HUMAN-latest-focus.html", focus_page(focus, len(action_rounds))),
    )
    if actual_receipt == original_receipt:
        # Only new outputs with the source-bound focus flag can claim a
        # latest-HUMAN attention workspace; every exact file is required.
        next_artifacts = (*full_next_files, *latest_files)
        legacy_slots = False
    elif actual_receipt == receipt_bytes(previous_binding):
        # Pre-attention originals had blank NEXT HUMAN room but no focus files.
        next_artifacts = full_next_files
        legacy_slots = True
    elif actual_receipt == receipt_bytes(oldest_binding):
        # Historical pre-continuation originals have neither optional feature.
        next_artifacts = ()
        legacy_slots = True
    else:
        raise Hold("HOLD: source-bound private history receipt changed")
    absent = {filename for filename, _ in (*full_next_files, *latest_files)}
    present = {filename for filename, _ in next_artifacts}
    for filename in absent - present:
        if (room / filename).exists() or (room / filename).is_symlink():
            raise Hold("HOLD: historical PRIVATE history mixed with new format files")
    required = (
        ("PRIVATE-HUMAN-action-history-receipt.json", actual_receipt),
        *next_artifacts,
        ("PRIVATE-HUMAN-action-history.csv", csv_history(export)),
        ("PRIVATE-HUMAN-action-history.html",
         overview(summaries, len(selected), copies, legacy_slots=legacy_slots)),
        ("PRIVATE-HUMAN-action-history-studio.html",
         history_studio(summaries, len(selected), len(action_rounds))),
    )
    for filename, original_bytes in required:
        if private_input(str(room / filename), 65536) != original_bytes:
            raise Hold("HOLD: original PRIVATE HUMAN chronology artifact changed")
    print("HOLD: original-bound PRIVATE HUMAN action chronology reopened read-only")
    print("OPEN LOCALLY: " + str(room / "PRIVATE-HUMAN-action-history-studio.html"))
    return 3
