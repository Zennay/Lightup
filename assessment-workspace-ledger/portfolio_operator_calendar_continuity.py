#!/usr/bin/env python3
"""Prepare a NEW manual PRIVATE HUMAN calendar round from exact originals.

No previous HUMAN date, status or question is assumed to represent an
appointment, an authenticated worker, actual remediation or consent.
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
from pathlib import Path
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page,
    new_private, object_unique, private_parent, read_owner_file,
    reject, write_private,
)
from portfolio_focus import local_path
from portfolio_operator_calendar import (
    HEADERS, admit_proposals, csv_template, day, read_original, receipt_document,
)

SCHEMA = "lightup.private.workspace-ledger-human-calendar-continuity-draft.v1"


def read_complete_previous(args):
    paths = [
        args.inbox, args.history, args.followup, args.operator_csv,
        args.previous_csv, args.previous_receipt, args.private_parent,
    ]
    if any(not local_path(path) for path in paths) or len(paths) != len(set(paths)):
        reject("PRIVATE HOLD: original previous HUMAN calendar paths must be distinct")
    private_parent(args.private_parent)
    if day(args.reference_day) is None:
        reject("PRIVATE HOLD: explicit HUMAN reference day required")
    originals, owners, items = read_original(args)
    previous_csv = read_owner_file(args.previous_csv, MAX_MANIFEST)
    previous_receipt = read_owner_file(args.previous_receipt, MAX_MANIFEST)
    old_rows = admit_proposals(previous_csv, items, digest(originals[2]))
    try:
        parsed = json.loads(
            previous_receipt.decode("utf-8"), object_pairs_hook=object_unique,
            parse_constant=lambda _: reject("PRIVATE HOLD: invalid nonfinite original receipt"),
        )
    except (UnicodeError, TypeError, ValueError) as exc:
        raise Hold("PRIVATE HOLD: previous original HUMAN calendar receipt unreadable") from exc
    if type(parsed) is not dict or type(parsed.get("human_selected_reference_day")) is not str:
        reject("PRIVATE HOLD: malformed original HUMAN calendar receipt")
    old_reference = parsed["human_selected_reference_day"]
    if day(old_reference) is None:
        reject("PRIVATE HOLD: previous original HUMAN reference day not valid")
    expected = receipt_document(originals, digest(originals[2]), previous_csv,
                                old_rows, old_reference)
    if parsed != expected or previous_receipt != canonical(parsed):
        reject("PRIVATE HOLD: previous original source-bound HUMAN calendar not accepted")
    return originals, items, previous_csv, previous_receipt, old_rows, old_reference


def new_csv(items, rows, sha, mode):
    source = io.StringIO(newline="")
    writer = csv.writer(source, lineterminator="\n")
    writer.writerow(HEADERS)
    for original, old in zip(items, rows):
        previous = [old["proposed_human_review_day"], old["human_attention_priority"],
                    old["private_human_discussion_question"]]
        manual = previous if mode == "carry" else ["", "unset", ""]
        writer.writerow([
            sha, original["original_proposed_human_owner_label"],
            original["local_case"], original["historical_transition"],
            original["original_kit"],
            original["original_owner_human_reply_stage"],
            original["human_operator_followup_stage"], *manual,
        ])
    return source.getvalue().encode("utf-8")


def run(args):
    if args.mode not in ("blank", "carry"):
        reject("PRIVATE HOLD: explicit HUMAN continuity mode required")
    original, items, previous_csv, previous_receipt, old_rows, old_reference = read_complete_previous(args)
    source_sha = digest(original[2])
    upcoming = new_csv(items, old_rows, source_sha, args.mode)
    new_rows = admit_proposals(upcoming, items, source_sha)
    if len(upcoming) > MAX_MANIFEST or len(new_rows) != len(items):
        reject("PRIVATE HOLD: full original HUMAN next-round CSV too large")
    snapshot = read_complete_previous(args)
    if (snapshot[0] != original or snapshot[2] != previous_csv or
            snapshot[3] != previous_receipt or snapshot[4] != old_rows):
        reject("PRIVATE HOLD: original HUMAN continuity source bytes changed")
    manifest = {
        "schema": SCHEMA, "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_owner_inbox_sha256": digest(original[0]),
        "original_history_sha256": digest(original[1]),
        "original_operator_followup_sha256": source_sha,
        "previous_original_calendar_csv_sha256": digest(previous_csv),
        "previous_original_calendar_receipt_sha256": digest(previous_receipt),
        "previous_human_reference_day": old_reference,
        "new_human_reference_day": args.reference_day,
        "human_explicit_proposal_carry_mode": args.mode,
        "previous_human_proposed_date_count": sum(bool(x["proposed_human_review_day"]) for x in old_rows),
        "new_human_proposed_date_count": sum(bool(x["proposed_human_review_day"]) for x in new_rows),
        "original_human_source_slot_count": len(items),
    }
    overview = html_page(
        "LightUp PRIVATE next HUMAN proposed-calendar DRAFT",
        "<p><strong>PRIVATE local HUMAN draft, not a completed review, "
        "verified fix, authorization or real booking.</strong> Previous original "
        "HUMAN date proposals are " +
        ("explicitly copied for manual review" if args.mode == "carry"
         else "deliberately cleared into a new HUMAN round") +
        ". All source slots remain present; every HUMAN action needs fresh "
        "manual choice and native original-source intake. No real assigned "
        "owner, actual deadline, messaging, task or scan.</p>"
        "<p>Previous proposed HUMAN dates: " +
        str(manifest["previous_human_proposed_date_count"]) +
        "; next proposed dates: " + str(manifest["new_human_proposed_date_count"]) +
        "; original HUMAN slots: " + str(len(items)) +
        "; explicit reference day selected. This counts-only view contains "
        "no owner labels, case IDs, hashes, private text or original paths.</p>",
    )
    if len(canonical(manifest)) > MAX_MANIFEST or len(overview.encode("utf-8")) > MAX_MANIFEST:
        reject("PRIVATE HOLD: private original HUMAN continuity receipt too large")
    directory = new_private(args.private_parent)
    try:
        write_private(directory, "HUMAN-proposed-calendar-NEXT-DRAFT.csv", upcoming)
        write_private(directory, "PRIVATE-HUMAN-continuity-DRAFT.json", canonical(manifest))
        write_private(directory, "OPEN-PRIVATE.html", overview)
    except BaseException:
        shutil.rmtree(directory)
        raise
    print("PRIVATE HOLD: explicit HUMAN calendar next-round draft; still requires native receive")
    print(str(Path(directory) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(
        description="Original source-bound PRIVATE HUMAN next-round draft, never a booking"
    )
    parser.add_argument("--history", required=True)
    parser.add_argument("--inbox", required=True)
    parser.add_argument("--followup", required=True)
    parser.add_argument("--operator-csv", required=True)
    parser.add_argument("--previous-csv", required=True)
    parser.add_argument("--previous-receipt", required=True)
    parser.add_argument("--reference-day", required=True)
    parser.add_argument("--mode", choices=("blank", "carry"), required=True)
    parser.add_argument("--private-parent", required=True)
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original HUMAN next-round continuity refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
