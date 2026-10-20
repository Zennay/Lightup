#!/usr/bin/env python3
"""Receive a browser-selected source-minimal HUMAN action chronology offline.

Do NOT treat browser filters, identical human choices or human attention as a
privacy verdict, an authenticated reviewer or authority to disclose.
Reopen all original source-bound completed HUMAN receipts before every output.
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

from notes import Hold, private_directory, private_input, file_new, save_json
from privacy_triage import FALSE_FLAGS
from privacy_triage_discussion_history import source_state, reopen_history

SCHEMA = "lightup.private_human_action_history_selected_receipt.v1"
HEADER = (
    "original_ordinal", "human_round", "human_step",
    "human_stage_changed", "private_question_present",
    "private_question_changed",
)
BOOL_FIELDS = ("stage_changed", "question_present", "question_changed")


def expected_rows(originals: list[dict]) -> list[tuple]:
    return [
        (str(row["ordinal"]), str(row["round"]), row["step"],
         "TRUE" if row["stage_changed"] else "FALSE",
         "TRUE" if row["question_present"] else "FALSE",
         "TRUE" if row["question_changed"] else "FALSE")
        for row in originals
    ]


def csv_exact(rows: list[tuple]) -> bytes:
    """The exact original offline history browser's quoted-fields wire format."""
    lines = [",".join(HEADER)]
    for row in rows:
        lines.append(",".join('"' + str(v).replace('"', '""') + '"' for v in row))
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def admit_csv(raw: bytes, originals: list[dict]) -> list[tuple]:
    if not raw or len(raw) > 65536 or b"\x00" in raw:
        raise Hold("HOLD: selected PRIVATE original HUMAN history CSV oversized or missing")
    try:
        text = raw.decode("utf-8", "strict")
        if text.startswith("\ufeff") or not text.endswith("\r\n"):
            raise ValueError("noncanonical")
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        lines = list(reader)
        if (not lines or lines[0] != list(HEADER)
                or not 1 <= len(lines)-1 <= len(originals)):
            raise ValueError("header or count")
        selected = [tuple(row) for row in lines[1:]]
        if any(len(row) != len(HEADER) for row in selected):
            raise ValueError("extra fields")
        original_fields = expected_rows(originals)
        indices = {tuple(row): index for index, row in enumerate(original_fields)}
        previous = -1
        for row in selected:
            index = indices.get(row)
            if index is None or index <= previous:
                raise ValueError("unknown, repeated or reordered source HUMAN row")
            previous = index
        if raw != csv_exact(selected):
            raise ValueError("changed original browser CSV bytes")
        return selected
    except (ValueError, UnicodeError, csv.Error):
        raise Hold("HOLD: invalid or unbound PRIVATE selected HUMAN history") from None


def page(selected: list[tuple], total: int, rounds: int) -> bytes:
    lines = []
    for ordinal, round_no, step, changed, question, question_changed in selected:
        reasons = []
        if changed == "TRUE":
            reasons.append("HUMAN action differs from previous declared round")
        if question_changed == "TRUE":
            reasons.append("PRIVATE human question changed; text withheld")
        if question == "TRUE":
            reasons.append("PRIVATE human question exists; text withheld")
        if not reasons:
            reasons.append("No literal change is NOT a verified fix")
        lines.append("<li>Original #" + html.escape(ordinal) +
                     ", manually declared HUMAN round " + html.escape(round_no) +
                     " — <strong>" + html.escape(step) + "</strong>: " +
                     html.escape("; ".join(reasons)) + "</li>")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN selected action-history discussion</title>
<style>body{max-width:880px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui}
aside{border-left:5px solid #b14527;background:#fff1eb;padding:1rem}
li{padding:8px;border-bottom:1px solid #ccd}</style>
<h1>PRIVATE manually selected HUMAN chronology discussion</h1>
<aside><b>HOLD · PLAN/LAB ONLY · NO PRIVACY CLEARANCE.</b>
Only original-bound HUMAN stages and Boolean private note-change indicators
from manually supplied offline completed rounds. Source selection is not
authenticated human judgment, consent, verified remediation, a security
risk ranking, recipient authority or permission to disclose.</aside>
<p>Manually selected original HUMAN rows: """ + str(len(selected)) +
            """ of """ + str(total) + """. Original manually ordered rounds: """ +
            str(rounds) + """ (not authenticated chronology).</p><ol>""" +
            "".join(lines) + """</ol><footer>No original raw or masked notes,
customer findings, sources, source-byte hashes, free HUMAN questions or
reviewer identities are embedded. This private discussion is not the native
complete original source-bound HUMAN review. No auto-delivery, assessment,
client contact, model, network, grant or release.</footer></html>""").encode("utf-8")


def receipt_for(sources, manifest, decisions, packets, selected_raw,
                selected, action_rounds, round_shas,
                previous_history_receipt, raw, chosen) -> dict:
    return {
        "schema": SCHEMA, "claimed_status": "HOLD",
        "human_only": True, "original_count": len(sources),
        "original_selected_count": len(selected),
        "manually_ordered_rounds": len(action_rounds),
        "selected_human_rows": len(chosen),
        "original_manifest_sha256_unsigned": manifest,
        "original_human_csv_sha256_unsigned": decisions,
        "original_reviewer_csv_sha256_unsigned": [
            row["csv_sha256_unsigned"] for row in packets],
        "original_received_selected_sha256_unsigned": sha256(selected_raw).hexdigest(),
        "original_history_receipt_sha256_unsigned": sha256(previous_history_receipt).hexdigest(),
        "original_action_csv_sha256_unsigned": round_shas,
        "exact_browser_selection_sha256_unsigned": sha256(raw).hexdigest(),
        "not_authorized_or_authenticated": True,
        **{flag: False for flag in FALSE_FLAGS},
    }


def receive(original: str, reviews: list[str], room_name: str,
            final_rooms: list[str], history_name: str,
            selected_csv: str, parent_name: str) -> int:
    # The original history room is NOT itself an authority. Read-only re-admit
    # its exact bytes from all original source and completed review packets.
    reopen_history(original, reviews, room_name, final_rooms, history_name)
    (sources, manifest, decisions, packets, selected_raw, selected,
     action_rounds, records, round_shas, pairs, export) = source_state(
        original, reviews, room_name, final_rooms)
    raw = private_input(selected_csv, 65536)
    chosen = admit_csv(raw, records)
    previous_history_receipt = private_input(str(
        private_directory(history_name) /
        "PRIVATE-HUMAN-action-history-receipt.json"), 65536)
    parent = private_directory(parent_name)
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-history-selection-",
                                  dir=parent))
    os.chmod(output, 0o700)
    completed = False
    try:
        save_json(output / "PRIVATE-HUMAN-history-selected-receipt.json",
                  receipt_for(sources, manifest, decisions, packets,
                              selected_raw, selected, action_rounds, round_shas,
                              previous_history_receipt, raw, chosen))
        file_new(output / "PRIVATE-HUMAN-history-selected.csv", raw)
        file_new(output / "PRIVATE-HUMAN-history-selected.html",
                 page(chosen, len(records), len(action_rounds)))
        completed = True
        print("HOLD: original-bound PRIVATE selected HUMAN chronology received")
        print("OPEN LOCALLY: " + str(output / "PRIVATE-HUMAN-history-selected.html"))
        return 3
    finally:
        if not completed:
            shutil.rmtree(output)



def reopen_selected(original: str, reviews: list[str], room_name: str,
                    final_rooms: list[str], history_name: str,
                    selected_room: str) -> int:
    """Read-only byte-exact source/reviewer/round/reception reopener."""
    reopen_history(original, reviews, room_name, final_rooms, history_name)
    (sources, manifest, decisions, packets, selected_raw, selected,
     action_rounds, records, round_shas, pairs, export) = source_state(
        original, reviews, room_name, final_rooms)
    folder = private_directory(selected_room)
    raw = private_input(
        str(folder / "PRIVATE-HUMAN-history-selected.csv"), 65536)
    chosen = admit_csv(raw, records)
    prior = private_input(
        str(private_directory(history_name) /
            "PRIVATE-HUMAN-action-history-receipt.json"), 65536)
    expected_receipt = receipt_for(
        sources, manifest, decisions, packets, selected_raw, selected,
        action_rounds, round_shas, prior, raw, chosen)
    canonical = (
        json.dumps(expected_receipt, indent=2, sort_keys=True,
                   ensure_ascii=False) + "\n").encode("utf-8")
    if (private_input(
            str(folder / "PRIVATE-HUMAN-history-selected-receipt.json"), 65536)
            != canonical):
        raise Hold("HOLD: original-bound PRIVATE selected HUMAN history receipt changed")
    if (private_input(str(folder / "PRIVATE-HUMAN-history-selected.html"), 65536)
            != page(chosen, len(records), len(action_rounds))):
        raise Hold("HOLD: original-bound PRIVATE selected HUMAN history page changed")
    print("HOLD: original-bound selected HUMAN history reopened read-only")
    print("OPEN LOCALLY: " + str(folder / "PRIVATE-HUMAN-history-selected.html"))
    return 3
