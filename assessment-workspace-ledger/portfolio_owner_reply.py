#!/usr/bin/env python3
"""Offline PRIVATE original-packet-bound HUMAN reply, never proof of identity.

A proposed HUMAN owner can annotate only original selected rows from one
PRIVATE owner workroom. The result is an unsigned historical draft, never a
security assessment, authorization, grant, authenticated recipient or task.
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter
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
from portfolio_delta import valid_day
from portfolio_focus_owner_handoff import (
    COLUMNS, REPLY_HEADERS, REPLY_STAGES, SCHEMA as OWNER_SCHEMA,
)

SCHEMA = "lightup.private.workspace-ledger-owner-human-reply.v1"
OWNER_KEYS = {
    "schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation",
    "proposed_human_owner_label", "original_source_portfolio_sha256",
    "original_source_meeting_sha256", "original_review_return_sha256",
    "human_rows_only_for_selected_owner",
}
MAX_ROWS = 2048


def hexdigest(value):
    return type(value) is str and len(value) == 64 and all(
        letter in "0123456789abcdef" for letter in value
    )


def read_owner_packet(path):
    raw = read_owner_file(path, MAX_MANIFEST)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite packet"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise Hold("PRIVATE HOLD: unreadable PRIVATE owner packet") from exc
    if (type(doc) is not dict or set(doc) != OWNER_KEYS or
        doc["schema"] != OWNER_SCHEMA or
        not literal_false_authority(doc["authority"], FLAGS) or
        doc["historical_only"] is not True or
        any(doc[field] is not False for field in (
            "sources_reopened", "recipient_authenticated", "consent_assumed",
            "actions_dispatched", "appointments_booked", "verified_remediation"
        )) or
        any(not hexdigest(doc[field]) for field in (
            "original_source_portfolio_sha256",
            "original_source_meeting_sha256", "original_review_return_sha256"
        )) or raw != canonical(doc)):
        reject("PRIVATE HOLD: owner packet is not the original canonical source shape")
    owner = doc["proposed_human_owner_label"]
    if type(owner) is not str or not owner or owner != owner.strip():
        reject("PRIVATE HOLD: unsafe proposed HUMAN owner label")
    safe_human(owner, 80)
    rows = doc["human_rows_only_for_selected_owner"]
    if type(rows) is not list or not 1 <= len(rows) <= MAX_ROWS:
        reject("PRIVATE HOLD: invalid number of original HUMAN owner rows")
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != set(COLUMNS):
            reject("PRIVATE HOLD: incomplete original owner source row")
        identity = (row["local_case"], row["historical_transition"], row["original_kit"])
        if any(type(v) is not int for v in identity) or not (
            1 <= identity[0] <= 8 and 1 <= identity[1] <= 11 and
            1 <= identity[2] <= 12
        ) or identity in seen:
            reject("PRIVATE HOLD: conflicting original HUMAN source slots")
        seen.add(identity)
        if (row["original_human_priority"] not in (
            "human_urgent", "near_term", "routine", "unset"
        ) or row["human_review_stage"] not in (
            "needs_discussion", "proposed_followup", "hold"
        )):
            reject("PRIVATE HOLD: unsupported original HUMAN metadata")
        date = row["original_proposed_day"]
        if type(date) is not str or len(date) > 10 or (
            date and not valid_day(date)
        ):
            reject("PRIVATE HOLD: invalid original proposed HUMAN date")
        for name, bound in (
            ("original_private_human_next_step", 240),
            ("private_human_meeting_note", 240)
        ):
            if type(row[name]) is not str or "\r" in row[name] or (
                "\n" in row[name] or "\t" in row[name]
            ):
                reject("PRIVATE HOLD: unsafe original HUMAN note")
            safe_human(row[name], bound)
    return raw, doc, rows


def read_reply_csv(data, originals, packet_sha):
    try:
        reader = csv.DictReader(io.StringIO(data.decode("utf-8"), newline=""),
                                strict=True)
        if reader.fieldnames != list(REPLY_HEADERS):
            reject("PRIVATE HOLD: HUMAN reply CSV header/order mismatch")
        rows = list(reader)
    except (UnicodeError, ValueError, csv.Error) as exc:
        raise Hold("PRIVATE HOLD: invalid HUMAN reply CSV") from exc
    if len(rows) != len(originals):
        reject("PRIVATE HOLD: HUMAN reply must cover all original owner rows")
    accepted = []
    for original, row in zip(originals, rows):
        if type(row) is not dict or set(row) != set(REPLY_HEADERS):
            reject("PRIVATE HOLD: extra/missing HUMAN reply fields")
        for field in ("local_case", "historical_transition", "original_kit"):
            if row[field] != str(original[field]):
                reject("PRIVATE HOLD: HUMAN reply mismatched original source slot")
        if row["original_owner_packet_sha256"] != packet_sha:
            reject("PRIVATE HOLD: reply for different original owner packet")
        stage, note = row["human_reply_stage"], row["private_reply_note"]
        if stage not in REPLY_STAGES or type(note) is not str or any(
            c in note for c in "\n\r\t"
        ):
            reject("PRIVATE HOLD: malformed HUMAN reply")
        safe_human(note, 240)
        accepted.append({
            "local_case": original["local_case"],
            "historical_transition": original["historical_transition"],
            "original_kit": original["original_kit"],
            "human_reply_stage": stage,
            "private_reply_note": note,
        })
    return accepted


def counts_html(rows):
    counts = Counter(row["human_reply_stage"] for row in rows)
    body = [
        "<p><strong>PRIVATE HUMAN-only original-owner reply; DRAFT/HOLD.</strong> "
        "No identity or distribution permission was authenticated, no actual "
        "target or original customer source reopened, no appointment/task "
        "booked or dispatched, no real security finding or fix verified.</p>",
        "<p>HUMAN proposed follow-up slots: " + str(len(rows)) + ".</p>",
        "<table><thead><tr><th>Historical HUMAN reply draft</th><th>Count</th>"
        "</tr></thead><tbody>",
    ]
    for stage in REPLY_STAGES:
        body.append("<tr><td>" + html.escape(stage) + "</td><td>" +
                    str(counts[stage]) + "</td></tr>")
    body.append("</tbody></table><p>No proposed owner identities, notes, "
                "original hashes, paths or other private sources included. "
                "Keep even counts-only output PRIVATE.</p>")
    return html_page("LightUp · PRIVATE unsigned HUMAN reply summary", "".join(body))


def detailed_html(owner, original, decisions):
    body = [
        "<p><strong>PRIVATE HUMAN response draft, never authenticated.</strong> "
        "Original proposed HUMAN owner: " + html.escape(owner, quote=True) +
        ". This exact label is NOT a confirmed real person, recipient, "
        "authorization or permission to share.</p>",
        "<table><thead><tr><th>Original slot</th><th>Original PRIVATE HUMAN note</th>"
        "<th>Original discussion note</th><th>New HUMAN response stage</th>"
        "<th>PRIVATE HUMAN reply</th></tr></thead><tbody>",
    ]
    for previous, current in zip(original, decisions):
        body.append(
            "<tr><td>" + str(current["local_case"]) + "/" +
            str(current["historical_transition"]) + "/" +
            str(current["original_kit"]) + "</td><td>" +
            html.escape(previous["original_private_human_next_step"], quote=True) +
            "</td><td>" +
            html.escape(previous["private_human_meeting_note"], quote=True) +
            "</td><td>" +
            html.escape(current["human_reply_stage"]) + "</td><td>" +
            html.escape(current["private_reply_note"], quote=True) + "</td></tr>"
        )
    body.append("</tbody></table><p>All entries remain local unsigned HUMAN "
                "proposals. No permission, scheduling, dispatch, assessment, "
                "security change or consent follows from this packet.</p>")
    return html_page("LightUp · PRIVATE HUMAN owner response", "".join(body))


def run(args):
    paths = (args.owner_packet, args.review, args.private_parent)
    if any(not local_path(path) for path in paths) or len(set(paths)) != 3:
        reject("PRIVATE HOLD: use distinct canonical PRIVATE paths")
    private_parent(args.private_parent)
    raw, packet, rows = read_owner_packet(args.owner_packet)
    review = read_owner_file(args.review, MAX_MANIFEST)
    accepted = read_reply_csv(review, rows, digest(raw))
    if (read_owner_packet(args.owner_packet)[0] != raw or
        read_owner_file(args.review, MAX_MANIFEST) != review):
        reject("PRIVATE HOLD: HUMAN reply sources changed during local admission")
    payload = {
        "schema": SCHEMA, "authority": FLAGS,
        "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_owner_packet_sha256": digest(raw),
        "original_reply_csv_sha256": digest(review),
        "proposed_human_owner_label": packet["proposed_human_owner_label"],
        "original_source_portfolio_sha256": packet["original_source_portfolio_sha256"],
        "original_source_meeting_sha256": packet["original_source_meeting_sha256"],
        "original_review_return_sha256": packet["original_review_return_sha256"],
        "human_reply_rows": accepted,
    }
    outputs = {
        "OPEN-PRIVATE.html": counts_html(accepted),
        "PRIVATE-HUMAN-owner-reply.html": detailed_html(
            packet["proposed_human_owner_label"], rows, accepted
        ),
        "PRIVATE-HUMAN-owner-reply.json": canonical(payload),
        "PRIVATE-HUMAN-original-reply.csv": review,
    }
    if any(len(value if isinstance(value, bytes) else value.encode("utf-8")) >
           MAX_MANIFEST for value in outputs.values()):
        reject("PRIVATE HOLD: owner reply exceeds bounded output")
    folder = new_private(args.private_parent)
    try:
        for name, data in outputs.items():
            write_private(folder, name, data)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: historical HUMAN response prepared, never sent or authorized")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(
        description="Finalize one source-bound PRIVATE HUMAN owner reply"
    )
    parser.add_argument("--owner-packet", required=True,
                        help="Original PRIVATE-HUMAN-owner.json")
    parser.add_argument("--review", required=True,
                        help="Original source-bound human-edited owner reply CSV, 0600")
    parser.add_argument("--private-parent", required=True,
                        help="Existing owner-only 0700 path outside source checkout")
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, TypeError, ValueError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: HUMAN owner reply not admitted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
