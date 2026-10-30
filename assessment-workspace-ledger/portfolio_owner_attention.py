#!/usr/bin/env python3
"""Minimum-necessary offline PRIVATE HUMAN owner discussion handoff.

Reopens an original native HUMAN inbox, exact HUMAN discussion CSV and its
source-bound native finalizer JSON. Creates one owner-selected discussion
packet only. This is not recipient identity, actual remediation or authority.
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
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page,
    literal_false_authority, new_private, object_unique, private_parent,
    read_owner_file, reject, safe_human, write_private,
)
from portfolio_focus import local_path
from portfolio_owner_inbox_review import (
    SCHEMA as DISCUSSION_SCHEMA, STAGES, read_inbox, read_review,
)

SCHEMA = "lightup.private.workspace-ledger-owner-human-attention.v1"
DISCUSSION_KEYS = {
    "schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation", "original_inbox_sha256",
    "original_human_review_csv_sha256", "original_portfolio_sha256",
    "original_meeting_sha256", "original_review_return_sha256",
    "private_human_discussion_rows",
}
COLUMNS = (
    "local_case", "historical_transition", "original_kit",
    "original_human_stage", "original_owner_reply_stage",
    "human_triage_stage", "private_human_triage_note",
)


def read_discussion(path, inbox_raw, inbox_doc, csv_raw, original):
    raw = read_owner_file(path, MAX_MANIFEST)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite HUMAN discussion"))
    except (TypeError, UnicodeError, ValueError) as exc:
        raise Hold("PRIVATE HOLD: unreadable original HUMAN discussion") from exc
    if (type(doc) is not dict or set(doc) != DISCUSSION_KEYS or
        doc["schema"] != DISCUSSION_SCHEMA or
        not literal_false_authority(doc["authority"], FLAGS) or
        doc["historical_only"] is not True or
        any(doc[k] is not False for k in (
            "sources_reopened", "recipient_authenticated", "consent_assumed",
            "actions_dispatched", "appointments_booked", "verified_remediation"
        )) or raw != canonical(doc) or
        doc["original_inbox_sha256"] != digest(inbox_raw) or
        doc["original_human_review_csv_sha256"] != digest(csv_raw) or
        any(doc[k] != inbox_doc[source] for k, source in (
            ("original_portfolio_sha256", "original_portfolio_sha256"),
            ("original_meeting_sha256", "original_meeting_sha256"),
            ("original_review_return_sha256", "original_review_return_sha256")
        ))):
        reject("PRIVATE HOLD: original HUMAN discussion not exact-inbox-bound")
    exact = read_review(csv_raw, original, digest(inbox_raw))
    if doc["private_human_discussion_rows"] != exact:
        reject("PRIVATE HOLD: original HUMAN discussion differs from native CSV")
    return raw, exact


def minimal_html(rows):
    counts = Counter(row["human_triage_stage"] for row in rows)
    content = [
        "<p><strong>PRIVATE, source-minimal HUMAN-only follow-up.</strong> "
        "All labels, notes, local case identifiers, hashes and proposed "
        "dates are omitted from this count-only document. No authenticated "
        "receiver, verified fix, real task assignment, consent, grant, "
        "scan, or scheduled work is represented.</p>",
        "<p>Original private selected HUMAN slots: " + str(len(rows)) + ".</p>",
        "<table><thead><tr><th>Human proposal stage</th><th>Count</th>"
        "</tr></thead><tbody>",
    ]
    for stage in STAGES:
        content.append("<tr><td>" + html.escape(stage) + "</td><td>" +
                       str(counts[stage]) + "</td></tr>")
    content.append("</tbody></table><p>All original source and other-human "
                   "labels remain PRIVATE and unchanged.</p>")
    return html_page("LightUp PRIVATE minimum owner HUMAN follow-up summary",
                     "".join(content))


def detailed_html(owner, rows):
    content = [
        "<p><strong>PRIVATE human-only proposed owner handoff, DRAFT/HOLD.</strong> "
        "Original HUMAN owner label: " + html.escape(owner, quote=True) +
        ". This label does NOT authenticate a person or confer permission "
        "to share. No customer data was rescanned or finding verified.</p>",
        "<table><thead><tr><th>Original source slot</th><th>Original HUMAN status</th>"
        "<th>Original HUMAN reply</th><th>Local HUMAN follow-up proposal</th>"
        "<th>PRIVATE HUMAN note</th></tr></thead><tbody>",
    ]
    for r in rows:
        def v(key):
            return html.escape(str(r[key]), quote=True)
        content.append(
            "<tr><td>" + v("local_case") + " / " +
            v("historical_transition") + " / " + v("original_kit") +
            "</td><td>" + v("original_human_stage") +
            "</td><td>" + v("original_owner_reply_stage") +
            "</td><td>" + v("human_triage_stage") +
            "</td><td>" + v("private_human_triage_note") +
            "</td></tr>"
        )
    content.append("</tbody></table><p>No other owner group is exported. "
                   "All original inputs remain untouched. Neither review "
                   "nor handoff changes real authorization, scan access, "
                   "tasks, scheduling or remediation status.</p>")
    return html_page("LightUp PRIVATE minimum owner HUMAN discussion", "".join(content))


def as_csv(rows):
    result = io.StringIO(newline="")
    writer = csv.writer(result, lineterminator="\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([row[c] for c in COLUMNS])
    return result.getvalue()


def run(args):
    paths = [args.inbox, args.discussion, args.original_review_csv, args.private_parent]
    if any(not local_path(p) for p in paths) or len(set(paths)) != len(paths):
        reject("PRIVATE HOLD: distinct original canonical local input files required")
    owner = args.owner
    if type(owner) is not str or not owner or owner != owner.strip():
        reject("PRIVATE HOLD: exact proposed HUMAN owner label required")
    safe_human(owner, 80)
    private_parent(args.private_parent)
    inbox_raw, inbox_doc, original = read_inbox(args.inbox)
    csv_raw = read_owner_file(args.original_review_csv, MAX_MANIFEST)
    discussion_raw, all_rows = read_discussion(
        args.discussion, inbox_raw, inbox_doc, csv_raw, original
    )
    rows = []
    for row in all_rows:
        if row["original_proposed_human_owner"] == owner:
            rows.append({k: row[k] for k in COLUMNS})
    if not rows:
        reject("PRIVATE HOLD: owner label absent from original HUMAN discussion")
    if (read_inbox(args.inbox)[0] != inbox_raw or
        read_owner_file(args.original_review_csv, MAX_MANIFEST) != csv_raw or
        read_discussion(args.discussion, inbox_raw, inbox_doc, csv_raw, original)[0] !=
        discussion_raw):
        reject("PRIVATE HOLD: original HUMAN follow-up source changed before export")
    result = {
        "schema": SCHEMA, "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_inbox_sha256": digest(inbox_raw),
        "original_discussion_sha256": digest(discussion_raw),
        "original_human_review_csv_sha256": digest(csv_raw),
        "original_proposed_human_owner_label": owner,
        "selected_original_human_discussion_rows_only": rows,
    }
    exports = {
        "OPEN-PRIVATE.html": minimal_html(rows),
        "PRIVATE-HUMAN-owner-attention.html": detailed_html(owner, rows),
        "PRIVATE-HUMAN-owner-attention.csv": as_csv(rows),
        "PRIVATE-HUMAN-owner-attention.json": canonical(result),
    }
    if any(len(v if isinstance(v, bytes) else v.encode("utf-8")) >
           MAX_MANIFEST for v in exports.values()):
        reject("PRIVATE HOLD: original minimum-necessary HUMAN output too large")
    folder = new_private(args.private_parent)
    try:
        for file, value in exports.items():
            write_private(folder, file, value)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: source-bound minimal HUMAN owner meeting packet; nothing shared")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    ap = argparse.ArgumentParser(
        description="Prepare source-bound owner-only PRIVATE HUMAN discussion without dispatch"
    )
    ap.add_argument("--inbox", required=True,
                    help="Original native PRIVATE-HUMAN-owner-inbox.json")
    ap.add_argument("--discussion", required=True,
                    help="Original finalized PRIVATE-HUMAN-inbox-review.json")
    ap.add_argument("--original-review-csv", required=True,
                    help="Original complete edited HUMAN-inbox-review-template.csv")
    ap.add_argument("--owner", required=True,
                    help="One EXACT original proposed HUMAN owner label")
    ap.add_argument("--private-parent", required=True,
                    help="Existing 0700 operator-private folder")
    args = ap.parse_args()
    try:
        return run(args)
    except (Hold, OSError, TypeError, ValueError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: minimum-necessary HUMAN owner handoff refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
