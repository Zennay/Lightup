#!/usr/bin/env python3
"""Local PRIVATE source-exact HUMAN inbox discussion follow-up.

Re-admits the ORIGINAL unsigned native inbox JSON and complete HUMAN CSV.
This does not authenticate a client, owner, security assessment or recipient,
and never grants, schedules, dispatches, or verifies remediation.
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
from portfolio_owner_inbox import (
    SCHEMA as INBOX_SCHEMA, INBOX_REVIEW_HEADERS, OUTPUT_COLUMNS, MAX_OWNERS,
)

SCHEMA = "lightup.private.workspace-ledger-human-owner-inbox-review.v1"
STAGES = ("needs_discussion", "proposed_followup", "hold")
INBOX_KEYS = {
    "schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation",
    "original_portfolio_sha256", "original_meeting_sha256",
    "original_review_return_sha256",
    "original_owner_reply_packets_in_explicit_human_order",
}
PACKET_KEYS = {
    "owner_label", "original_owner_packet_sha256",
    "original_owner_reply_sha256", "original_reply_csv_sha256", "human_rows",
}
MAX_ROWS = 2048


def hex_digest(value):
    return type(value) is str and len(value) == 64 and all(
        item in "0123456789abcdef" for item in value
    )


def read_inbox(path):
    raw = read_owner_file(path, MAX_MANIFEST)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite HUMAN inbox"))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: unreadable HUMAN inbox") from exc
    if (type(doc) is not dict or set(doc) != INBOX_KEYS or
        doc["schema"] != INBOX_SCHEMA or
        not literal_false_authority(doc["authority"], FLAGS) or
        doc["historical_only"] is not True or
        any(doc[field] is not False for field in (
            "sources_reopened", "recipient_authenticated", "consent_assumed",
            "actions_dispatched", "appointments_booked", "verified_remediation"
        )) or raw != canonical(doc) or
        any(not hex_digest(doc[k]) for k in (
            "original_portfolio_sha256", "original_meeting_sha256",
            "original_review_return_sha256"
        ))):
        reject("PRIVATE HOLD: unsigned HUMAN inbox not original canonical native format")
    packets = doc["original_owner_reply_packets_in_explicit_human_order"]
    if type(packets) is not list or not 1 <= len(packets) <= MAX_OWNERS:
        reject("PRIVATE HOLD: invalid original HUMAN inbox owner group")
    rows, owners, ids = [], set(), set()
    for packet in packets:
        if (type(packet) is not dict or set(packet) != PACKET_KEYS or
            any(not hex_digest(packet[k]) for k in (
                "original_owner_packet_sha256",
                "original_owner_reply_sha256", "original_reply_csv_sha256"
            ))):
            reject("PRIVATE HOLD: unreadable original owner response group")
        label = packet["owner_label"]
        if type(label) is not str or not label or label != label.strip():
            reject("PRIVATE HOLD: malformed original proposed owner")
        safe_human(label, 80)
        if label in owners:
            reject("PRIVATE HOLD: ambiguous repeated HUMAN owner label")
        owners.add(label)
        own_rows = packet["human_rows"]
        if type(own_rows) is not list or not own_rows:
            reject("PRIVATE HOLD: original owner HUMAN rows missing")
        for row in own_rows:
            if type(row) is not dict or set(row) != set(OUTPUT_COLUMNS):
                reject("PRIVATE HOLD: missing original HUMAN source proposal")
            identity = tuple(row[k] for k in (
                "local_case", "historical_transition", "original_kit"
            ))
            if (any(type(v) is not int for v in identity) or
                not 1 <= identity[0] <= 8 or
                not 1 <= identity[1] <= 11 or
                not 1 <= identity[2] <= 12 or identity in ids):
                reject("PRIVATE HOLD: ambiguous original source case identity")
            ids.add(identity)
            if (row["original_proposed_human_owner"] != label or
                row["original_human_priority"] not in (
                    "human_urgent", "near_term", "routine", "unset"
                ) or
                row["original_human_stage"] not in STAGES or
                row["new_human_reply_stage"] not in STAGES or
                type(row["private_human_reply_text"]) is not str or
                any(c in row["private_human_reply_text"] for c in "\r\n\t")):
                reject("PRIVATE HOLD: original HUMAN owner/review proposal malformed")
            safe_human(row["private_human_reply_text"], 240)
            rows.append(row)
            if len(rows) > MAX_ROWS:
                reject("PRIVATE HOLD: too many original HUMAN inbox slots")
    return raw, doc, rows


def read_review(data, original_rows, source_sha):
    try:
        reader = csv.DictReader(io.StringIO(data.decode("utf-8"), newline=""),
                                strict=True)
        if reader.fieldnames != list(INBOX_REVIEW_HEADERS):
            reject("PRIVATE HOLD: original HUMAN inbox review CSV schema changed")
        incoming = list(reader)
    except (ValueError, UnicodeError, csv.Error) as exc:
        raise Hold("PRIVATE HOLD: malformed HUMAN inbox follow-up CSV") from exc
    if len(incoming) != len(original_rows):
        reject("PRIVATE HOLD: every original HUMAN inbox row must be reviewed")
    choices = []
    for source, row in zip(original_rows, incoming):
        if type(row) is not dict or set(row) != set(INBOX_REVIEW_HEADERS):
            reject("PRIVATE HOLD: HUMAN inbox review fields missing or foreign")
        for key in ("local_case", "historical_transition", "original_kit"):
            if row[key] != str(source[key]):
                reject("PRIVATE HOLD: HUMAN inbox case slot/order drift")
        if row["original_inbox_sha256"] != source_sha:
            reject("PRIVATE HOLD: HUMAN inbox review from different original source")
        stage, note = row["human_triage_stage"], row["private_human_triage_note"]
        if (stage not in STAGES or type(note) is not str or
            any(c in note for c in "\n\r\t")):
            reject("PRIVATE HOLD: invalid HUMAN inbox triage")
        safe_human(note, 240)
        choices.append({
            "local_case": source["local_case"],
            "historical_transition": source["historical_transition"],
            "original_kit": source["original_kit"],
            "original_proposed_human_owner": source["original_proposed_human_owner"],
            "original_human_stage": source["original_human_stage"],
            "original_owner_reply_stage": source["new_human_reply_stage"],
            "human_triage_stage": stage,
            "private_human_triage_note": note,
        })
    return choices


def minimal_html(choices):
    stages = Counter(row["human_triage_stage"] for row in choices)
    body = [
        "<p><strong>PRIVATE HUMAN inbox discussion draft only.</strong> "
        "No verified finding, task, owner identity, security progress, real "
        "client/operator consent, grant, scan or dispatch. The original "
        "case/owner labels and HUMAN notes are absent from this count-only view.</p>",
        "<p>Original HUMAN slots represented: " + str(len(choices)) + ".</p>",
        "<table><thead><tr><th>Human-only attention stage</th><th>Count</th>"
        "</tr></thead><tbody>",
    ]
    for stage in STAGES:
        body.append("<tr><td>" + html.escape(stage) + "</td><td>" +
                    str(stages[stage]) + "</td></tr>")
    body.append("</tbody></table><p>All original private inputs remain "
                "untouched. No recipient was verified or contacted.</p>")
    return html_page("LightUp PRIVATE HUMAN inbox conversation summary", "".join(body))


def detailed_html(choices):
    body = [
        "<p><strong>Owner-private offline HUMAN meeting discussion only.</strong> "
        "The exact original unsigned inbox was re-admitted, not independently "
        "authenticated or re-scanned. These notes are NOT verified remediations "
        "or real work orders.</p>",
        "<table><thead><tr><th>Original proposed owner</th><th>Case / transition / kit</th>"
        "<th>Original HUMAN stage</th><th>Original reply proposal</th>"
        "<th>Local HUMAN discussion proposal</th><th>PRIVATE HUMAN note</th>"
        "</tr></thead><tbody>",
    ]
    for r in choices:
        def val(key):
            return html.escape(str(r[key]), quote=True)
        body.append(
            "<tr><td>" + val("original_proposed_human_owner") +
            "</td><td>" + val("local_case") + " / " +
            val("historical_transition") + " / " + val("original_kit") +
            "</td><td>" + val("original_human_stage") +
            "</td><td>" + val("original_owner_reply_stage") +
            "</td><td>" + val("human_triage_stage") +
            "</td><td>" + val("private_human_triage_note") + "</td></tr>"
        )
    body.append("</tbody></table><p>No automatic assignment, approval, "
                "schedule, or scan follows from these HUMAN draft choices.</p>")
    return html_page("LightUp PRIVATE source-bound HUMAN inbox review", "".join(body))


def run(args):
    if (not local_path(args.inbox) or not local_path(args.review) or
        not local_path(args.private_parent) or
        len({args.inbox, args.review, args.private_parent}) != 3):
        reject("PRIVATE HOLD: require three distinct absolute original paths")
    private_parent(args.private_parent)
    source, doc, original = read_inbox(args.inbox)
    csv_data = read_owner_file(args.review, MAX_MANIFEST)
    chosen = read_review(csv_data, original, digest(source))
    # Entire original source plus all human choices must stay byte-identical
    # before creating the new confidential output directory.
    if (read_inbox(args.inbox)[0] != source or
        read_owner_file(args.review, MAX_MANIFEST) != csv_data):
        reject("PRIVATE HOLD: unsigned original HUMAN inbox changed before output")
    result = {
        "schema": SCHEMA, "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_inbox_sha256": digest(source),
        "original_human_review_csv_sha256": digest(csv_data),
        "original_portfolio_sha256": doc["original_portfolio_sha256"],
        "original_meeting_sha256": doc["original_meeting_sha256"],
        "original_review_return_sha256": doc["original_review_return_sha256"],
        "private_human_discussion_rows": chosen,
    }
    outputs = {
        "OPEN-PRIVATE.html": minimal_html(chosen),
        "PRIVATE-HUMAN-inbox-review.html": detailed_html(chosen),
        "PRIVATE-HUMAN-inbox-review.json": canonical(result),
        "PRIVATE-HUMAN-original-inbox-review.csv": csv_data,
    }
    if any(len(x if isinstance(x, bytes) else x.encode("utf-8")) >
           MAX_MANIFEST for x in outputs.values()):
        reject("PRIVATE HOLD: HUMAN inbox review exceeds private size bound")
    folder = new_private(args.private_parent)
    try:
        for name, data in outputs.items():
            write_private(folder, name, data)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: HUMAN inbox conversation recorded; no action or permission")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(
        description="Finalize only private historical HUMAN discussion on one original inbox"
    )
    parser.add_argument("--inbox", required=True,
                        help="Original PRIVATE-HUMAN-owner-inbox.json")
    parser.add_argument("--review", required=True,
                        help="Complete original-inbox-bound HUMAN review CSV")
    parser.add_argument("--private-parent", required=True,
                        help="Existing owner-private 0700 folder outside source repo")
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original HUMAN inbox discussion cannot be admitted",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
