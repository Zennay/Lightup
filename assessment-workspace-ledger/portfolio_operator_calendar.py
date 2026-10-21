#!/usr/bin/env python3
"""PRIVATE source-bound HUMAN-only proposed review calendar; never a scheduler.

Only consumes original completed HUMAN follow-up from its original owner inbox,
history and unchanged full CSV. Dates are proposals, never appointments/tasks.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import date
import html
import io
import json
from pathlib import Path
import re
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    private_parent, read_owner_file, reject, safe_human, write_private,
    object_unique,
)
from portfolio_focus import local_path
from portfolio_owner_change_briefs import admit as native_admit

SCHEMA = "lightup.private.workspace-ledger-human-review-calendar.v1"
HEADERS = (
    "original_operator_followup_sha256",
    "original_proposed_human_owner_label",
    "local_case", "historical_transition", "original_kit",
    "original_owner_human_reply_stage", "original_operator_human_stage",
    "proposed_human_review_day", "human_attention_priority",
    "private_human_discussion_question",
)
PRIORITIES = ("unset", "human_urgent", "near_term", "routine")
MAX_ROWS = 2048


def day(value):
    if not value:
        return None
    if type(value) is not str or not re.fullmatch(r"20\d{2}-[01]\d-[0-3]\d", value):
        reject("PRIVATE HOLD: proposed HUMAN day must be exact 20xx-mm-dd")
    try:
        chosen = date.fromisoformat(value)
    except ValueError as exc:
        raise Hold("PRIVATE HOLD: nonexistent proposed HUMAN review day") from exc
    return chosen


def read_original(args):
    raw_inbox, raw_history, raw_followup, raw_csv, owners = native_admit(args)
    items = [r for rows in owners.values() for r in rows]
    if not items or len(items) > MAX_ROWS:
        reject("PRIVATE HOLD: expected 1–2048 original owner HUMAN source slots")
    return (raw_inbox, raw_history, raw_followup, raw_csv), owners, items


def baseline(item, sha):
    return (
        sha, item["original_proposed_human_owner_label"],
        str(item["local_case"]), str(item["historical_transition"]),
        str(item["original_kit"]), item["original_owner_human_reply_stage"],
        item["human_operator_followup_stage"],
    )


def csv_template(items, sha):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(HEADERS)
    for row in items:
        writer.writerow([*baseline(row, sha), "", "unset", ""])
    return buffer.getvalue()


def admit_proposals(payload, items, sha):
    try:
        source = io.StringIO(payload.decode("utf-8"), newline="")
        reader = csv.DictReader(source, strict=True)
        if reader.fieldnames != list(HEADERS):
            reject("PRIVATE HOLD: full original HUMAN calendar columns required")
        given = list(reader)
    except (UnicodeError, ValueError, csv.Error) as exc:
        raise Hold("PRIVATE HOLD: malformed original HUMAN calendar CSV") from exc
    if len(given) != len(items):
        reject("PRIVATE HOLD: all original HUMAN source rows required in original order")
    planned = []
    for original, row in zip(items, given):
        if type(row) is not dict or set(row) != set(HEADERS) or None in row:
            reject("PRIVATE HOLD: missing/extra HUMAN calendar CSV cells")
        if tuple(row[name] for name in HEADERS[:7]) != baseline(original, sha):
            reject("PRIVATE HOLD: original HUMAN owner, source slot or status drift")
        target = row["proposed_human_review_day"]
        priority = row["human_attention_priority"]
        note = row["private_human_discussion_question"]
        day(target)
        if (priority not in PRIORITIES or type(note) is not str or
                any(ch in note for ch in "\r\n\t")):
            reject("PRIVATE HOLD: invalid HUMAN priority/question")
        safe_human(note, 240)
        planned.append({
            "original_proposed_human_owner_label": original["original_proposed_human_owner_label"],
            "local_case": original["local_case"],
            "historical_transition": original["historical_transition"],
            "original_kit": original["original_kit"],
            "original_owner_human_reply_stage": original["original_owner_human_reply_stage"],
            "original_operator_human_stage": original["human_operator_followup_stage"],
            "proposed_human_review_day": target,
            "human_attention_priority": priority,
            "private_human_discussion_question": note,
        })
    return planned


def bucket(value, reference):
    if not value:
        return "no_day_proposed"
    if value < reference:
        return "earlier_proposed_day"
    if value == reference:
        return "selected_reference_day"
    return "later_proposed_day"


def private_detail(owner, rows, reference):
    ordered = sorted(rows, key=lambda r: (
        r["proposed_human_review_day"] or "9999-12-31",
        PRIORITIES.index(r["human_attention_priority"]),
        r["local_case"], r["historical_transition"], r["original_kit"],
    ))
    lines = [
        "<p><strong>PRIVATE HUMAN proposed calendar; no actual assignment, "
        "deadline, appointment or consent.</strong> Label is NOT authenticated: ",
        html.escape(owner, quote=True),
        ". Operator-selected comparison day: ", reference, ".</p>",
        "<table><thead><tr><th>Original slot</th><th>Owner HUMAN reply</th>"
        "<th>Operator HUMAN proposal</th><th>Proposed review day</th>"
        "<th>Human priority</th><th>Private discussion question</th>"
        "</tr></thead><tbody>",
    ]
    for r in ordered:
        fields = [
            str(r["local_case"]) + " / " + str(r["historical_transition"]) +
            " / " + str(r["original_kit"]),
            r["original_owner_human_reply_stage"],
            r["original_operator_human_stage"],
            r["proposed_human_review_day"] or "none",
            r["human_attention_priority"],
            r["private_human_discussion_question"],
        ]
        lines.append("<tr>" + "".join(
            "<td>" + html.escape(value, quote=True) + "</td>" for value in fields
        ) + "</tr>")
    return html_page("LightUp PRIVATE HUMAN proposed review calendar",
                     "".join(lines) + "</tbody></table>")


def index_html(items, owners, reference):
    stages = Counter(bucket(row["proposed_human_review_day"], reference) for row in items)
    priorities = Counter(row["human_attention_priority"] for row in items)
    body = (
        "<p><strong>PRIVATE HUMAN proposal overview (not authenticated).</strong> "
        "No source IDs, names, original file paths, hashes, discussion questions "
        "or human free text in this index. A proposed day is NOT an appointment "
        "or actual task deadline. No scans, consent, verified remediation or "
        "permissions. Operator-selected comparison day: " +
        html.escape(reference) + ".</p><p>Original HUMAN source slots: " +
        str(len(items)) + "; proposed HUMAN owner rooms: " + str(len(owners)) + ".</p>"
        "<table><thead><tr><th>Proposed day category</th><th>Count</th>"
        "</tr></thead><tbody>" +
        "".join("<tr><td>" + k + "</td><td>" + str(stages[k]) +
                "</td></tr>" for k in (
                "earlier_proposed_day", "selected_reference_day",
                "later_proposed_day", "no_day_proposed")) +
        "</tbody></table><table><thead><tr><th>HUMAN priority</th><th>Count</th>"
        "</tr></thead><tbody>" +
        "".join("<tr><td>" + k + "</td><td>" + str(priorities[k]) +
                "</td></tr>" for k in PRIORITIES) + "</tbody></table>"
    )
    for ordinal, folder in enumerate(owners, 1):
        body += ('<p>PRIVATE proposed owner room ' + str(ordinal) +
                 ': <a href="' + html.escape(folder, quote=True) +
                 '/PRIVATE-HUMAN-proposed-calendar.html">open</a></p>')
    return html_page("LightUp PRIVATE HUMAN calendar counts", body)


def receipt_document(originals, sha, payload, rows, reference_day):
    return {
        "schema": SCHEMA, "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_owner_inbox_sha256": digest(originals[0]),
        "original_history_sha256": digest(originals[1]),
        "original_operator_followup_sha256": sha,
        "original_operator_csv_sha256": digest(originals[3]),
        "human_proposed_calendar_csv_sha256": digest(payload),
        "human_selected_reference_day": reference_day,
        "human_only_proposed_review_rows": rows,
    }


def reopen(args):
    paths = [args.inbox, args.history, args.followup, args.operator_csv,
             args.proposed_csv, args.receipt, args.private_parent]
    if any(not local_path(path) for path in paths) or len(paths) != len(set(paths)):
        reject("PRIVATE HOLD: original HUMAN calendar reopen paths must be distinct")
    private_parent(args.private_parent)
    if day(args.reference_day) is None:
        reject("PRIVATE HOLD: explicit HUMAN comparison day required")
    originals, _, items = read_original(args)
    payload = read_owner_file(args.proposed_csv, MAX_MANIFEST)
    rows = admit_proposals(payload, items, digest(originals[2]))
    raw = read_owner_file(args.receipt, MAX_MANIFEST)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite receipt"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: invalid original HUMAN calendar receipt") from exc
    expected = receipt_document(originals, digest(originals[2]), payload,
                                rows, args.reference_day)
    if type(doc) is not dict or raw != canonical(doc) or doc != expected:
        reject("PRIVATE HOLD: original HUMAN receipt, CSV or source-byte mismatch")
    if (read_original(args)[0] != originals or
            read_owner_file(args.proposed_csv, MAX_MANIFEST) != payload or
            read_owner_file(args.receipt, MAX_MANIFEST) != raw):
        reject("PRIVATE HOLD: original HUMAN calendar input drift")
    print("PRIVATE REVIEW_ONLY: exact original HUMAN proposal CSV and unsigned "
          "receipt reopened; no actual task, recipient authentication or appointment")
    return 2


def run(args):
    if args.mode == "reopen":
        return reopen(args)
    paths = [args.inbox, args.history, args.followup, args.operator_csv,
             args.private_parent]
    if args.mode == "receive":
        paths.append(args.proposed_csv)
    if (any(not local_path(path) for path in paths) or
            len(paths) != len(set(paths))):
        reject("PRIVATE HOLD: unique absolute original/private paths required")
    private_parent(args.private_parent)
    reference = day(args.reference_day)
    if reference is None:
        reject("PRIVATE HOLD: operator must select a HUMAN reference day")
    originals, owners, items = read_original(args)
    sha = digest(originals[2])
    payload = (read_owner_file(args.proposed_csv, MAX_MANIFEST)
               if args.mode == "receive" else csv_template(items, sha).encode("utf-8"))
    rows = admit_proposals(payload, items, sha)
    if read_original(args)[0] != originals:
        reject("PRIVATE HOLD: original source-bound HUMAN files changed")
    if args.mode == "receive" and read_owner_file(args.proposed_csv, MAX_MANIFEST) != payload:
        reject("PRIVATE HOLD: HUMAN proposed CSV changed during native intake")

    # Source-free browser software accompanies both local HUMAN flows.
    from portfolio_operator_calendar_studio import render as calendar_studio
    software = calendar_studio()
    output = new_private(args.private_parent)
    try:
        write_private(output, "PRIVATE-HUMAN-calendar-studio.html", software)
        if args.mode == "receive":
            folders = []
            for owner, _ in owners.items():
                room = new_private(output)
                selected = [r for r in rows if r["original_proposed_human_owner_label"] == owner]
                write_private(room, "PRIVATE-HUMAN-proposed-calendar.html",
                              private_detail(owner, selected, args.reference_day))
                folders.append(Path(room).name)
            receipt = receipt_document(originals, sha, payload, rows,
                                       args.reference_day)
            write_private(output, "PRIVATE-HUMAN-proposed-calendar.json", canonical(receipt))
            write_private(output, "PRIVATE-HUMAN-proposed-calendar.csv", payload)
            write_private(output, "OPEN-PRIVATE.html",
                          index_html(rows, folders, args.reference_day))
        else:
            write_private(output, "HUMAN-proposed-calendar-template.csv", payload)
            write_private(output, "OPEN-PRIVATE.html",
                          index_html(rows, [], args.reference_day))
    except BaseException:
        shutil.rmtree(output)
        raise
    print("PRIVATE HOLD: local HUMAN-only review calendar " + args.mode +
          "; no scheduling/dispatch/recipient verification")
    print(str(Path(output) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(
        description="Offline PRIVATE HUMAN-only review calendar, never real scheduling")
    parser.add_argument("mode", choices=("prepare", "receive", "reopen"))
    parser.add_argument("--history", required=True)
    parser.add_argument("--inbox", required=True)
    parser.add_argument("--followup", required=True)
    parser.add_argument("--operator-csv", required=True)
    parser.add_argument("--proposed-csv")
    parser.add_argument("--receipt")
    parser.add_argument("--reference-day", required=True, help="Explicit 20xx-mm-dd")
    parser.add_argument("--private-parent", required=True)
    args = parser.parse_args()
    if ((args.mode == "prepare" and (args.proposed_csv or args.receipt)) or
            (args.mode == "receive" and (not args.proposed_csv or args.receipt)) or
            (args.mode == "reopen" and (not args.proposed_csv or not args.receipt))):
        parser.error("prepare: no CSV/receipt; receive: CSV; reopen: CSV + receipt")
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original HUMAN-only calendar refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
