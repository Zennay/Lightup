#!/usr/bin/env python3
"""Source-exact private HUMAN proposed-review calendar revision history.

Two to eight explicit offline original-bound HUMAN revisions; never real
appointments, security progress, consent, authentication or task completion.
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
    object_unique, private_parent, read_owner_file, reject, write_private,
)
from portfolio_focus import local_path
from portfolio_operator_calendar import (
    SCHEMA as CALENDAR_SCHEMA, admit_proposals, day, read_original, receipt_document,
)

SCHEMA = "lightup.private.workspace-ledger-human-calendar-history.v1"
MAX_REVISIONS = 8
COLUMNS = (
    "local_case", "historical_transition", "original_kit",
    "first_human_proposed_review_day", "latest_human_proposed_review_day",
    "first_human_priority", "latest_human_priority",
    "human_proposed_day_changed", "human_priority_changed",
    "private_human_question_changed",
)


def admit(args):
    receipts = args.calendar_receipts
    plans = args.proposed_csvs
    if (type(receipts) is not list or type(plans) is not list or
            not 2 <= len(receipts) == len(plans) <= MAX_REVISIONS):
        reject("PRIVATE HOLD: require 2–8 explicit full original HUMAN calendar receipt/CSV pairs")
    paths = [args.history, args.inbox, args.followup, args.operator_csv,
             args.private_parent, *receipts, *plans]
    if any(not local_path(p) for p in paths) or len(set(paths)) != len(paths):
        reject("PRIVATE HOLD: require distinct original source and private revision paths")
    private_parent(args.private_parent)
    originals, owners, items = read_original(args)
    versions = []
    for index, (receipt_path, csv_path) in enumerate(zip(receipts, plans), 1):
        receipt = read_owner_file(receipt_path, MAX_MANIFEST)
        csv_raw = read_owner_file(csv_path, MAX_MANIFEST)
        rows = admit_proposals(csv_raw, items, digest(originals[2]))
        try:
            doc = json.loads(receipt.decode("utf-8"), object_pairs_hook=object_unique,
                             parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite HUMAN calendar receipt"))
        except (ValueError, TypeError, UnicodeError) as exc:
            raise Hold("PRIVATE HOLD: unreadable original HUMAN calendar revision receipt") from exc
        if type(doc) is not dict:
            reject("PRIVATE HOLD: invalid original HUMAN revision format")
        reference = doc.get("human_selected_reference_day")
        if type(reference) is not str or day(reference) is None:
            reject("PRIVATE HOLD: original HUMAN revision reference day missing")
        expected = receipt_document(originals, digest(originals[2]), csv_raw,
                                    rows, reference)
        if (receipt != canonical(doc) or doc != expected or
                doc.get("schema") != CALENDAR_SCHEMA):
            reject("PRIVATE HOLD: original calendar revision not exactly source-bound")
        versions.append({
            "ordinal": index,
            "reference_day": reference,
            "receipt_sha256": digest(receipt),
            "full_csv_sha256": digest(csv_raw),
            "receipt_bytes": receipt,
            "csv_bytes": csv_raw,
            "rows": rows,
        })
    return originals, owners, versions


def changes(versions):
    first = versions[0]["rows"]
    last = versions[-1]["rows"]
    result = []
    counts = Counter()
    for index, (old, current) in enumerate(zip(first, last)):
        day_versions = [v["rows"][index]["proposed_human_review_day"] for v in versions]
        priority_versions = [v["rows"][index]["human_attention_priority"] for v in versions]
        question_versions = [v["rows"][index]["private_human_discussion_question"] for v in versions]
        day_changed = any(a != b for a, b in zip(day_versions, day_versions[1:]))
        priority_changed = any(a != b for a, b in zip(priority_versions, priority_versions[1:]))
        question_changed = any(a != b for a, b in zip(question_versions, question_versions[1:]))
        if day_changed: counts["days_changed"] += 1
        if priority_changed: counts["priorities_changed"] += 1
        if question_changed: counts["questions_changed"] += 1
        if day_changed or priority_changed or question_changed:
            counts["any_revision_changed"] += 1
        result.append({
            "original_proposed_human_owner_label": old["original_proposed_human_owner_label"],
            "local_case": old["local_case"],
            "historical_transition": old["historical_transition"],
            "original_kit": old["original_kit"],
            "first_human_proposed_review_day": day_versions[0],
            "latest_human_proposed_review_day": day_versions[-1],
            "first_human_priority": priority_versions[0],
            "latest_human_priority": priority_versions[-1],
            "human_proposed_day_changed": day_changed,
            "human_priority_changed": priority_changed,
            "private_human_question_changed": question_changed,
        })
    counts["slots"] = len(result)
    return result, counts


def selected(row):
    return any(row[key] for key in (
        "human_proposed_day_changed", "human_priority_changed",
        "private_human_question_changed",
    ))


def csv_text(rows):
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([row[k] for k in COLUMNS])
    return out.getvalue()


def detail_html(owner, rows, rounds):
    parts = [
        "<p><strong>PRIVATE HUMAN-only original source revisions.</strong> "
        "Proposed owner label is NOT an authenticated recipient: ",
        html.escape(owner, quote=True),
        ". Explicit native original HUMAN round count: ", str(rounds),
        ". Changed dates are NOT booked appointments, overdue real tasks, "
        "verified remediation, consent or security approval. No private HUMAN "
        "question text or hashes are displayed.</p>",
        "<table><thead><tr><th>Original slot</th><th>First proposed day</th>"
        "<th>Latest proposed day</th><th>First priority</th>"
        "<th>Latest priority</th><th>Day changed</th>"
        "<th>Priority changed</th><th>Private HUMAN question changed</th>"
        "</tr></thead><tbody>",
    ]
    for r in rows:
        fields = [
            str(r["local_case"]) + " / " + str(r["historical_transition"]) +
            " / " + str(r["original_kit"]),
            r["first_human_proposed_review_day"] or "not proposed",
            r["latest_human_proposed_review_day"] or "not proposed",
            r["first_human_priority"], r["latest_human_priority"],
            "yes" if r["human_proposed_day_changed"] else "no",
            "yes" if r["human_priority_changed"] else "no",
            "yes" if r["private_human_question_changed"] else "no",
        ]
        parts.append("<tr>" + "".join(
            "<td>" + html.escape(value, quote=True) + "</td>" for value in fields
        ) + "</tr>")
    return html_page("LightUp PRIVATE HUMAN calendar revision desk",
                     "".join(parts) + "</tbody></table>")


def index_html(groups, counter, round_count):
    body = (
        "<p><strong>PRIVATE original HUMAN-only proposal revision index.</strong>"
        " No original case identities, proposed owner labels, private questions, "
        "source SHA or file paths on this landing page. No appointments, "
        "authentication, real tasks, scans, grants, consent or security verdict. "
        "No changes is NOT evidence of a fix.</p><p>Explicit original HUMAN rounds: " +
        str(round_count) + "; total original slots: " + str(counter["slots"]) +
        "; changed HUMAN slots: " + str(counter["any_revision_changed"]) +
        "; proposed-day changes: " + str(counter["days_changed"]) +
        "; priority changes: " + str(counter["priorities_changed"]) +
        "; private-question changes: " + str(counter["questions_changed"]) +
        ".</p><table><thead><tr><th>PRIVATE owner room</th>"
        "<th>Selected HUMAN slots</th><th>Open locally</th>"
        "</tr></thead><tbody>"
    )
    for ordinal, (folder, count) in enumerate(groups, 1):
        body += (
            "<tr><td>" + str(ordinal) + "</td><td>" + str(count) +
            "</td><td><a href=\"" + html.escape(folder, quote=True) +
            "/PRIVATE-HUMAN-calendar-revision.html\">Open PRIVATE owner desk</a></td></tr>"
        )
    return html_page("LightUp PRIVATE HUMAN-only calendar history",
                     body + "</tbody></table>")


def run(args):
    originals, owners, versions = admit(args)
    rows, counts = changes(versions)
    again, fresh_owners, current = admit(args)
    if (again != originals or fresh_owners != owners or
            [(r["receipt_bytes"], r["csv_bytes"]) for r in current] !=
            [(r["receipt_bytes"], r["csv_bytes"]) for r in versions]):
        reject("PRIVATE HOLD: original HUMAN calendar revision sources drifted")
    root = new_private(args.private_parent)
    try:
        references = []
        for owner in owners:
            chosen = [r for r in rows if r["original_proposed_human_owner_label"] == owner]
            if args.changed_only:
                chosen = [r for r in chosen if selected(r)]
            room = new_private(root)
            write_private(room, "PRIVATE-HUMAN-calendar-revision.html",
                          detail_html(owner, chosen, len(versions)))
            write_private(room, "PRIVATE-HUMAN-calendar-revision.csv", csv_text(chosen))
            references.append((Path(room).name, len(chosen)))
        metadata = {
            "schema": SCHEMA, "authority": FLAGS, "historical_only": True,
            "sources_reopened": False, "recipient_authenticated": False,
            "consent_assumed": False, "actions_dispatched": False,
            "appointments_booked": False, "verified_remediation": False,
            "original_owner_inbox_sha256": digest(originals[0]),
            "original_history_sha256": digest(originals[1]),
            "original_operator_followup_sha256": digest(originals[2]),
            "changed_only": args.changed_only,
            "human_proposal_revision_receipts": [{
                "ordinal": v["ordinal"],
                "original_human_reference_day": v["reference_day"],
                "original_receipt_sha256": v["receipt_sha256"],
                "original_csv_sha256": v["full_csv_sha256"],
            } for v in versions],
            "human_only_revision_counts": dict(counts),
            "private_owner_rooms_in_original_order": [{
                "ordinal": i, "private_room": room, "selected_human_slots": number
            } for i, (room, number) in enumerate(references, 1)],
        }
        overview = index_html(references, counts, len(versions))
        if len(overview.encode("utf-8")) > MAX_MANIFEST or len(canonical(metadata)) > MAX_MANIFEST:
            reject("PRIVATE HOLD: HUMAN calendar revision output too large")
        write_private(root, "OPEN-PRIVATE.html", overview)
        write_private(root, "PRIVATE-HUMAN-calendar-revisions.json", canonical(metadata))
    except BaseException:
        shutil.rmtree(root)
        raise
    print("PRIVATE HOLD: original-source HUMAN calendar revisions recorded, no real action")
    print(str(Path(root) / "OPEN-PRIVATE.html"))
    return 3


def main():
    p = argparse.ArgumentParser(description="Compare 2–8 original HUMAN calendar receipts, no actual task")
    p.add_argument("--history", required=True)
    p.add_argument("--inbox", required=True)
    p.add_argument("--followup", required=True)
    p.add_argument("--operator-csv", required=True)
    p.add_argument("--calendar-receipt", dest="calendar_receipts", action="append", required=True)
    p.add_argument("--proposed-csv", dest="proposed_csvs", action="append", required=True)
    p.add_argument("--private-parent", required=True)
    p.add_argument("--changed-only", action="store_true")
    args = p.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original HUMAN calendar revisions refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
