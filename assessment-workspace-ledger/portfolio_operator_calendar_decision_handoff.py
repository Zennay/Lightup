#!/usr/bin/env python3
"""Carry manually proposed HUMAN calendar decisions back as a NEW local DRAFT.

Not actual scheduling, owner authentication, permission, findings, review
approval, grants, or completed remediation. Requires exact original receipts.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import io
from pathlib import Path
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page,
    new_private, private_parent, read_owner_file, reject, write_private,
)
from portfolio_focus import local_path
from portfolio_operator_calendar import (
    HEADERS as CALENDAR_HEADERS, baseline, read_original, admit_proposals,
)
from portfolio_operator_calendar_decisions import (
    original as read_decision_sources,
    receive_csv, reopen as reopen_decisions,
)


SCHEMA = "lightup.private.workspace-ledger-human-decision-handoff-draft.v1"


def handoff(items, selected, source_sha):
    rows = io.StringIO(newline="")
    writer = csv.writer(rows, lineterminator="\n")
    writer.writerow(CALENDAR_HEADERS)
    if len(items) != len(selected) or not items:
        reject("PRIVATE HOLD: complete source ordinal set required for HUMAN handoff")
    stage_counts = Counter()
    for index, (source, decision) in enumerate(zip(items, selected), 1):
        if (decision["original_human_source_ordinal"] != index or
                source["original_proposed_human_owner_label"] !=
                decision["original_proposed_human_owner_label"] or
                any(source[k] != decision[k] for k in (
                    "local_case", "historical_transition", "original_kit"))):
            reject("PRIVATE HOLD: original HUMAN handoff source mismatch")
        stage = decision["human_alignment_stage"]
        stage_counts[stage] += 1
        if stage == "human_alignment_proposed":
            proposed = [
                decision["human_selected_proposed_review_day"],
                decision["human_selected_priority"],
                decision["private_human_alignment_question"],
            ]
        else:
            # A HUMAN 'hold' or unresolved discussion must NOT silently
            # become a proposed appointment/priority or note in new round.
            proposed = ["", "unset", ""]
        writer.writerow([*baseline(source, source_sha), *proposed])
    return rows.getvalue().encode("utf-8"), stage_counts


def run(args):
    paths = [args.inbox, args.history, args.followup, args.operator_csv,
             args.private_parent, args.decisions_csv, args.decision_receipt,
             *args.calendar_receipts, *args.proposed_csvs]
    if any(not local_path(p) for p in paths) or len(set(paths)) != len(paths):
        reject("PRIVATE HOLD: distinct original owner-private sources required")
    private_parent(args.private_parent)

    # Required original complete review before any user-visible output.
    reopen_decisions(args)
    originals, _, items = read_original(args)
    decision_originals, _, rounds, source_rounds, sha, proposal_slots = read_decision_sources(args)
    if decision_originals != originals or len(proposal_slots) != len(items):
        reject("PRIVATE HOLD: inconsistent native original calendar source")
    chosen_raw = read_owner_file(args.decisions_csv, MAX_MANIFEST)
    decision_receipt = read_owner_file(args.decision_receipt, MAX_MANIFEST)
    choices = receive_csv(chosen_raw, proposal_slots, sha)
    csv_raw, stages = handoff(items, choices, digest(originals[2]))
    if len(csv_raw) > MAX_MANIFEST:
        reject("PRIVATE HOLD: original HUMAN handoff draft too large")
    # Independently admit the WHOLE new proposal draft as a source-bound
    # native calendar shape, but NEVER finalize it as an actual review.
    admitted = admit_proposals(csv_raw, items, digest(originals[2]))
    if len(admitted) != len(items):
        reject("PRIVATE HOLD: native original HUMAN draft incomplete")

    # Check unchanged original completed decision receipt/CSV and
    # 2–8 native source versions immediately before creating private output.
    reopen_decisions(args)
    again, _, same_items = read_original(args)
    if (again != originals or same_items != items or
            read_owner_file(args.decisions_csv, MAX_MANIFEST) != chosen_raw or
            read_owner_file(args.decision_receipt, MAX_MANIFEST) != decision_receipt):
        reject("PRIVATE HOLD: source-bound HUMAN decision changed before handoff")
    summary = html_page(
        "LightUp PRIVATE next HUMAN calendar draft",
        "<p><strong>PRIVATE HUMAN-only proposed next-round DRAFT.</strong>"
        " NOTHING has been booked, assigned, sent, authenticated or approved."
        " HUMAN alignment is only a proposed opinion. Earlier HUMAN HOLDs and"
        " unresolved discussions are deliberately blank in the new CSV."
        " Every original source slot is preserved and the native original"
        " calendar RECEIVER must be used again after MANUAL review.</p>"
        "<p>Original HUMAN slots: " + str(len(items)) +
        "; manually proposed HUMAN alignment slots: " +
        str(stages["human_alignment_proposed"]) +
        "; withheld HUMAN slots: " + str(stages["hold"]) +
        "; unresolved HUMAN slots: " + str(stages["needs_discussion"]) +
        ". This source-minimal page omits owner labels, source cases,"
        " source SHA, private notes, and original paths.</p>",
    )
    manifest = {
        "schema": SCHEMA, "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_owner_inbox_sha256": digest(originals[0]),
        "original_history_sha256": digest(originals[1]),
        "original_operator_followup_sha256": digest(originals[2]),
        "original_operator_followup_csv_sha256": digest(originals[3]),
        "original_calendar_proposal_set_sha256": sha,
        "original_human_decision_receipt_sha256": digest(decision_receipt),
        "original_human_decision_csv_sha256": digest(chosen_raw),
        "new_unreviewed_human_calendar_draft_sha256": digest(csv_raw),
        "human_only_stage_counts": dict(stages),
        "original_human_source_slot_count": len(items),
    }
    if len(summary.encode("utf-8")) > MAX_MANIFEST or len(canonical(manifest)) > MAX_MANIFEST:
        reject("PRIVATE HOLD: HUMAN proposed next-round handoff too large")
    parent = new_private(args.private_parent)
    try:
        write_private(parent, "OPEN-PRIVATE.html", summary)
        write_private(parent, "HUMAN-proposed-calendar-NEXT-DRAFT.csv", csv_raw)
        write_private(parent, "PRIVATE-HUMAN-decision-handoff-DRAFT.json", canonical(manifest))
    except BaseException:
        shutil.rmtree(parent)
        raise
    print("PRIVATE HOLD: HUMAN decision proposals handed to NEW unreviewed local calendar DRAFT")
    print(str(Path(parent) / "OPEN-PRIVATE.html"))
    return 3


def main():
    p = argparse.ArgumentParser(description="Source-exact HUMAN-only proposed calendar decisions to new unreviewed DRAFT")
    p.add_argument("--history", required=True)
    p.add_argument("--inbox", required=True)
    p.add_argument("--followup", required=True)
    p.add_argument("--operator-csv", required=True)
    p.add_argument("--calendar-receipt", dest="calendar_receipts", action="append", required=True)
    p.add_argument("--proposed-csv", dest="proposed_csvs", action="append", required=True)
    p.add_argument("--decisions-csv", required=True)
    p.add_argument("--decision-receipt", required=True)
    p.add_argument("--private-parent", required=True)
    args = p.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original HUMAN decision handoff refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
