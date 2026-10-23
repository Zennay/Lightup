#!/usr/bin/env python3
"""Private source-bound HUMAN calendar disagreement and decision desk.

Uses 2–8 original calendar receipts against ONE original owner inbox and
operator follow-up. Does not infer authenticated reviewers, real bookings,
verified findings, consent, grants, or that any proposal is complete.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import io
import json
from pathlib import Path
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    private_parent, read_owner_file, reject, safe_human, write_private,
    object_unique,
)
from portfolio_focus import local_path
from portfolio_operator_calendar import PRIORITIES, day
from portfolio_operator_calendar_history import admit as admit_versions

SCHEMA = "lightup.private.workspace-ledger-human-calendar-decisions.v1"
HEADERS = (
    "original_human_calendar_set_sha256",
    "original_human_source_ordinal",
    "original_proposed_human_owner_label",
    "local_case", "historical_transition", "original_kit",
    "human_day_proposals_differ", "human_priority_proposals_differ",
    "private_human_question_proposals_differ",
    "human_selected_proposed_review_day", "human_selected_priority",
    "private_human_alignment_question", "human_alignment_stage",
)
STAGES = ("needs_discussion", "hold", "human_alignment_proposed")
MAX_ROWS = 2048


def original(args):
    originals, owners, versions = admit_versions(args)
    if not versions or not versions[0]["rows"]:
        reject("PRIVATE HOLD: original HUMAN calendar proposal set empty")
    source_rounds = [{
        "ordinal": v["ordinal"],
        "original_receipt_sha256": v["receipt_sha256"],
        "original_complete_csv_sha256": v["full_csv_sha256"],
        "human_original_reference_day": v["reference_day"],
    } for v in versions]
    source_set_sha = digest(canonical({
        "original_owner_inbox_sha256": digest(originals[0]),
        "original_history_sha256": digest(originals[1]),
        "original_operator_followup_sha256": digest(originals[2]),
        "original_operator_csv_sha256": digest(originals[3]),
        "calendar_rounds_in_original_order": source_rounds,
    }))
    items = []
    for index, source in enumerate(versions[0]["rows"]):
        rows = [v["rows"][index] for v in versions]
        identities = [
            (r["original_proposed_human_owner_label"], r["local_case"],
             r["historical_transition"], r["original_kit"],
             r["original_owner_human_reply_stage"], r["original_operator_human_stage"])
            for r in rows
        ]
        if any(x != identities[0] for x in identities):
            reject("PRIVATE HOLD: unrelated original HUMAN calendar source slots")
        proposed_days = [r["proposed_human_review_day"] for r in rows]
        priorities = [r["human_attention_priority"] for r in rows]
        questions = [r["private_human_discussion_question"] for r in rows]
        items.append({
            "original_human_source_ordinal": index + 1,
            "original_proposed_human_owner_label": source["original_proposed_human_owner_label"],
            "local_case": source["local_case"],
            "historical_transition": source["historical_transition"],
            "original_kit": source["original_kit"],
            "human_day_proposals_differ": len(set(proposed_days)) > 1,
            "human_priority_proposals_differ": len(set(priorities)) > 1,
            "private_human_question_proposals_differ": len(set(questions)) > 1,
            "human_day_proposals_by_original_round": proposed_days,
            "human_priority_proposals_by_original_round": priorities,
        })
    if len(items) > MAX_ROWS:
        reject("PRIVATE HOLD: too many ORIGINAL HUMAN calendar source slots")
    return originals, owners, versions, source_rounds, source_set_sha, items


OPTIONS_SCHEMA = "lightup.private.workspace-ledger-human-calendar-options.v1"


def private_options(items, original_rounds, sha):
    return {
        "schema": OPTIONS_SCHEMA,
        "authority": FLAGS,
        "historical_only": True,
        "sources_reopened": False,
        "recipient_authenticated": False,
        "consent_assumed": False,
        "actions_dispatched": False,
        "appointments_booked": False,
        "verified_remediation": False,
        "original_human_calendar_set_sha256": sha,
        "original_human_round_count": len(original_rounds),
        "human_source_options_in_original_order": [{
            "original_human_source_ordinal": x["original_human_source_ordinal"],
            "original_proposed_human_owner_label": x["original_proposed_human_owner_label"],
            "local_case": x["local_case"],
            "historical_transition": x["historical_transition"],
            "original_kit": x["original_kit"],
            "human_day_proposals_differ": x["human_day_proposals_differ"],
            "human_priority_proposals_differ": x["human_priority_proposals_differ"],
            "private_human_question_proposals_differ":
                x["private_human_question_proposals_differ"],
            "human_day_proposals_by_original_round":
                x["human_day_proposals_by_original_round"],
            "human_priority_proposals_by_original_round":
                x["human_priority_proposals_by_original_round"],
        } for x in items],
    }


def source_cells(item, sha):
    return (
        sha, str(item["original_human_source_ordinal"]),
        item["original_proposed_human_owner_label"],
        str(item["local_case"]), str(item["historical_transition"]),
        str(item["original_kit"]),
        "yes" if item["human_day_proposals_differ"] else "no",
        "yes" if item["human_priority_proposals_differ"] else "no",
        "yes" if item["private_human_question_proposals_differ"] else "no",
    )


def draft(items, sha):
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(HEADERS)
    for item in items:
        writer.writerow([*source_cells(item, sha), "", "unset", "", "needs_discussion"])
    return out.getvalue().encode("utf-8")


def receive_csv(data, items, source_sha):
    try:
        reader = csv.DictReader(io.StringIO(data.decode("utf-8"), newline=""), strict=True)
        if reader.fieldnames != list(HEADERS):
            reject("PRIVATE HOLD: full original HUMAN decision sheet schema mismatch")
        incoming = list(reader)
    except (ValueError, UnicodeError, csv.Error) as exc:
        raise Hold("PRIVATE HOLD: original HUMAN decision sheet unreadable") from exc
    if len(incoming) != len(items):
        reject("PRIVATE HOLD: every original HUMAN slot must remain in decision sheet")
    selected = []
    for original, row in zip(items, incoming):
        if type(row) is not dict or set(row) != set(HEADERS) or None in row:
            reject("PRIVATE HOLD: wrong original HUMAN decision columns")
        if tuple(row[k] for k in HEADERS[:9]) != source_cells(original, source_sha):
            reject("PRIVATE HOLD: original HUMAN calendar source/owner/conflict drift")
        proposed_day = row["human_selected_proposed_review_day"]
        priority = row["human_selected_priority"]
        note = row["private_human_alignment_question"]
        stage = row["human_alignment_stage"]
        day(proposed_day)
        if (priority not in PRIORITIES or stage not in STAGES or
                type(note) is not str or any(c in note for c in "\r\n\t")):
            reject("PRIVATE HOLD: invalid HUMAN-only arbitration choices")
        safe_human(note, 240)
        selected.append({
            "original_human_source_ordinal": original["original_human_source_ordinal"],
            "original_proposed_human_owner_label": original["original_proposed_human_owner_label"],
            "local_case": original["local_case"],
            "historical_transition": original["historical_transition"],
            "original_kit": original["original_kit"],
            "human_day_proposals_differ": original["human_day_proposals_differ"],
            "human_priority_proposals_differ": original["human_priority_proposals_differ"],
            "private_human_question_proposals_differ":
                original["private_human_question_proposals_differ"],
            "human_selected_proposed_review_day": proposed_day,
            "human_selected_priority": priority,
            "private_human_alignment_question": note,
            "human_alignment_stage": stage,
        })
    return selected


def counts_html(items, versions, decisions=None, rooms=None):
    day_conflicts = sum(x["human_day_proposals_differ"] for x in items)
    priority_conflicts = sum(x["human_priority_proposals_differ"] for x in items)
    note_conflicts = sum(x["private_human_question_proposals_differ"] for x in items)
    counts = Counter(x["human_alignment_stage"] for x in (decisions or []))
    body = (
        "<p><strong>PRIVATE original HUMAN-only discussion agenda, NOT a "
        "signed consensus, approved finding, actual appointment, work assignment, "
        "client authorization, verified remediation or permission.</strong> "
        "No owner labels, case identities, original paths, source digests, "
        "or private HUMAN note text appear in this count-only index.</p>"
        "<p>Explicit original proposal sets: " + str(len(versions)) +
        "; original HUMAN slots: " + str(len(items)) +
        "; slots with differing proposed days: " + str(day_conflicts) +
        "; differing HUMAN priorities: " + str(priority_conflicts) +
        "; differing PRIVATE discussion questions: " + str(note_conflicts) +
        ".</p><p>Locally declared HUMAN alignment proposal statuses: " +
        ", ".join(k + ": " + str(counts[k]) for k in STAGES) + ".</p>"
    )
    for index, room in enumerate(rooms or [], 1):
        body += ("<p>PRIVATE owner room " + str(index) + ': <a href="' +
                 html.escape(room, quote=True) +
                 '/PRIVATE-HUMAN-owner-calendar-decisions.html">Open local HUMAN desk</a></p>')
    return html_page("LightUp PRIVATE HUMAN calendar decision counts", body)


def owner_html(owner, items, selected, rounds):
    body = [
        "<p><strong>PRIVATE original HUMAN-only proposed reconciliation.</strong>"
        " Label is NOT authenticated owner: " + html.escape(owner, quote=True) +
        ". Original proposals explicitly supplied: " + str(rounds) +
        ". All status and date values are HUMAN proposals only, not actual "
        "appointments or grants. Original private discussion question text "
        "is not repeated here, only whether it differs.</p>",
        "<table><thead><tr><th>Original slot</th><th>Proposed HUMAN days by round</th>"
        "<th>Proposed HUMAN priorities by round</th><th>Private question changed</th>"
        "<th>Human review stage</th><th>Selected HUMAN day</th>"
        "<th>Selected HUMAN priority</th><th>New PRIVATE question</th>"
        "</tr></thead><tbody>",
    ]
    for item, row in zip(items, selected):
        fields = [
            str(item["local_case"]) + " / " + str(item["historical_transition"]) +
            " / " + str(item["original_kit"]),
            " | ".join(x or "(blank)" for x in item["human_day_proposals_by_original_round"]),
            " | ".join(item["human_priority_proposals_by_original_round"]),
            "yes" if item["private_human_question_proposals_differ"] else "no",
            row["human_alignment_stage"],
            row["human_selected_proposed_review_day"] or "(blank)",
            row["human_selected_priority"],
            row["private_human_alignment_question"],
        ]
        body.append("<tr>" + "".join(
            "<td>" + html.escape(x, quote=True) + "</td>" for x in fields
        ) + "</tr>")
    return html_page("LightUp PRIVATE proposed HUMAN calendar discussion",
                     "".join(body) + "</tbody></table>")


def receipt_document(originals, rounds, sha, chosen_csv, choices):
    return {
        "schema": SCHEMA, "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_owner_inbox_sha256": digest(originals[0]),
        "original_history_sha256": digest(originals[1]),
        "original_operator_followup_sha256": digest(originals[2]),
        "original_full_operator_csv_sha256": digest(originals[3]),
        "original_calendar_proposal_set_sha256": sha,
        "original_calendar_rounds_in_order": rounds,
        "original_human_decision_csv_sha256": digest(chosen_csv),
        "human_only_proposed_resolution_rows": choices,
    }


def reopen(args):
    paths = [args.inbox, args.history, args.followup, args.operator_csv,
             args.private_parent, *args.calendar_receipts, *args.proposed_csvs,
             args.decisions_csv, args.decision_receipt]
    if any(not local_path(p) for p in paths) or len(set(paths)) != len(paths):
        reject("PRIVATE HOLD: require distinct original HUMAN decision sources")
    private_parent(args.private_parent)
    originals, _, versions, rounds, sha, items = original(args)
    chosen_csv = read_owner_file(args.decisions_csv, MAX_MANIFEST)
    choices = receive_csv(chosen_csv, items, sha)
    receipt_raw = read_owner_file(args.decision_receipt, MAX_MANIFEST)
    try:
        doc = json.loads(receipt_raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite decision receipt"))
    except (UnicodeError, TypeError, ValueError) as exc:
        raise Hold("PRIVATE HOLD: malformed original HUMAN decision receipt") from exc
    if (type(doc) is not dict or receipt_raw != canonical(doc) or
            doc != receipt_document(originals, rounds, sha, chosen_csv, choices)):
        reject("PRIVATE HOLD: original decision receipt not exact source bound")
    latest = original(args)
    if (latest[0] != originals or latest[3] != rounds or latest[4] != sha or
            latest[5] != items or
            [(r["receipt_bytes"], r["csv_bytes"]) for r in latest[2]] !=
            [(r["receipt_bytes"], r["csv_bytes"]) for r in versions] or
            read_owner_file(args.decisions_csv, MAX_MANIFEST) != chosen_csv or
            read_owner_file(args.decision_receipt, MAX_MANIFEST) != receipt_raw):
        reject("PRIVATE HOLD: original HUMAN decision source changed")
    print("PRIVATE REVIEW_ONLY: exact original HUMAN-only decision receipt reopened. "
          "No actual booking, grant, consent or authenticated reviewer.")
    return 2


def run(args):
    if args.mode == "reopen":
        return reopen(args)
    paths = [args.inbox, args.history, args.followup, args.operator_csv,
             args.private_parent, *args.calendar_receipts, *args.proposed_csvs]
    if args.mode == "receive":
        paths.append(args.decisions_csv)
    if any(not local_path(p) for p in paths) or len(set(paths)) != len(paths):
        reject("PRIVATE HOLD: original HUMAN decision paths must be distinct")
    originals, owners, versions, rounds, sha, items = original(args)
    choices = None
    chosen_csv = None
    if args.mode == "receive":
        chosen_csv = read_owner_file(args.decisions_csv, MAX_MANIFEST)
        choices = receive_csv(chosen_csv, items, sha)
    else:
        chosen_csv = draft(items, sha)
    old, new_owners, new_versions, new_rounds, new_sha, new_items = original(args)
    if (old != originals or new_owners != owners or new_sha != sha or
            new_rounds != rounds or new_items != items or
            [(v["receipt_bytes"], v["csv_bytes"]) for v in versions] !=
            [(v["receipt_bytes"], v["csv_bytes"]) for v in new_versions]):
        reject("PRIVATE HOLD: original HUMAN proposal source drift before output")
    if args.mode == "receive" and read_owner_file(args.decisions_csv, MAX_MANIFEST) != chosen_csv:
        reject("PRIVATE HOLD: original HUMAN decision CSV changed")
    from portfolio_operator_calendar_decision_studio import render as studio
    browser = studio()
    root = new_private(args.private_parent)
    try:
        write_private(root, "PRIVATE-HUMAN-calendar-decision-studio.html", browser)
        if args.mode == "prepare":
            write_private(root, "HUMAN-calendar-decision-template.csv", chosen_csv)
            # PRIVATE browser-only comparison payload: source-bound originals
            # but no earlier confidential HUMAN free question contents.
            original_options = canonical(private_options(items, rounds, sha))
            if len(original_options) > MAX_MANIFEST:
                reject("PRIVATE HOLD: original HUMAN options payload too large")
            write_private(root, "PRIVATE-HUMAN-original-calendar-options.json",
                          original_options)
            # Review original HUMAN alternatives BEFORE entering any decisions.
            # Original private questions are reduced to disagreement Booleans.
            local_defaults = receive_csv(chosen_csv, items, sha)
            folders = []
            for owner in owners:
                positions = [i for i, row in enumerate(items)
                             if row["original_proposed_human_owner_label"] == owner]
                room = new_private(root)
                write_private(room, "PRIVATE-HUMAN-owner-calendar-decisions.html",
                              owner_html(owner, [items[i] for i in positions],
                                         [local_defaults[i] for i in positions], len(versions)))
                folders.append(Path(room).name)
            write_private(root, "OPEN-PRIVATE.html",
                          counts_html(items, versions, local_defaults, folders))
        else:
            write_private(root, "PRIVATE-HUMAN-decision-original.csv", chosen_csv)
            write_private(root, "PRIVATE-HUMAN-decision-receipt.json", canonical(
                receipt_document(originals, rounds, sha, chosen_csv, choices)))
            folders = []
            for owner in owners:
                positions = [i for i, row in enumerate(items)
                             if row["original_proposed_human_owner_label"] == owner]
                room = new_private(root)
                write_private(room, "PRIVATE-HUMAN-owner-calendar-decisions.html",
                              owner_html(owner, [items[i] for i in positions],
                                         [choices[i] for i in positions], len(versions)))
                folders.append(Path(room).name)
            write_private(root, "OPEN-PRIVATE.html",
                          counts_html(items, versions, choices, folders))
        print("PRIVATE HOLD: HUMAN calendar decisions received as local proposals only" if choices else
              "PRIVATE HOLD: complete original-bound HUMAN calendar decision template prepared")
        print(str(Path(root) / "OPEN-PRIVATE.html"))
    except BaseException:
        shutil.rmtree(root)
        raise
    return 3


def main():
    parser = argparse.ArgumentParser(description=
        "Native PRIVATE HUMAN calendar proposal reconciliation (no real execution)")
    parser.add_argument("mode", choices=("prepare", "receive", "reopen"))
    parser.add_argument("--history", required=True)
    parser.add_argument("--inbox", required=True)
    parser.add_argument("--followup", required=True)
    parser.add_argument("--operator-csv", required=True)
    parser.add_argument("--calendar-receipt", dest="calendar_receipts", action="append", required=True)
    parser.add_argument("--proposed-csv", dest="proposed_csvs", action="append", required=True)
    parser.add_argument("--decisions-csv")
    parser.add_argument("--decision-receipt")
    parser.add_argument("--private-parent", required=True)
    args = parser.parse_args()
    if ((args.mode == "prepare" and (args.decisions_csv or args.decision_receipt)) or
            (args.mode == "receive" and (not args.decisions_csv or args.decision_receipt)) or
            (args.mode == "reopen" and (not args.decisions_csv or not args.decision_receipt))):
        parser.error("prepare: no decision files; receive: CSV; reopen: CSV + receipt")
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original HUMAN calendar decision refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
