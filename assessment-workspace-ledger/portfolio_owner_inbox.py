#!/usr/bin/env python3
"""PRIVATE multi-owner HUMAN reply inbox for one unchanged original review.

Reconciles selected original owner packets and their matching unsigned replies.
Never authenticates recipients, approves scans, dispatches work or verifies fixes.
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
from portfolio_delta import read_portfolio
from portfolio_focus import local_path
from portfolio_focus_history import read_return
from portfolio_focus_review import read_focus
from portfolio_focus_owner_handoff import (
    SCHEMA as OWNER_SCHEMA, match_owners,
)
from portfolio_owner_reply import (
    SCHEMA as REPLY_SCHEMA, read_owner_packet, read_reply_csv, REPLY_STAGES,
)

SCHEMA = "lightup.private.workspace-ledger-owner-reply-inbox.v1"
RETURN_KEYS = {
    "schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation", "original_owner_packet_sha256",
    "original_reply_csv_sha256", "proposed_human_owner_label",
    "original_source_portfolio_sha256", "original_source_meeting_sha256",
    "original_review_return_sha256", "human_reply_rows",
}
RETURN_ROWS = {
    "local_case", "historical_transition", "original_kit",
    "human_reply_stage", "private_reply_note",
}
OUTPUT_COLUMNS = (
    "local_case", "historical_transition", "original_kit",
    "original_proposed_human_owner", "original_human_priority",
    "original_human_stage", "new_human_reply_stage",
    "private_human_reply_text",
)
MAX_OWNERS = 8
INBOX_REVIEW_HEADERS = (
    "local_case", "historical_transition", "original_kit",
    "original_inbox_sha256", "human_triage_stage", "private_human_triage_note",
)


def inbox_review_template(packets, inbox_sha):
    """Original-inbox-bound HUMAN discussion draft. No actual task creation."""
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(INBOX_REVIEW_HEADERS)
    for packet in packets:
        for row in packet["human_rows"]:
            writer.writerow((
                row["local_case"], row["historical_transition"],
                row["original_kit"], inbox_sha, "needs_discussion", ""
            ))
    return out.getvalue()




def expected_original_packet(owner, rows, source_sha, meeting_sha, review_sha):
    return {
        "schema": OWNER_SCHEMA, "authority": FLAGS,
        "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "proposed_human_owner_label": owner,
        "original_source_portfolio_sha256": source_sha,
        "original_source_meeting_sha256": meeting_sha,
        "original_review_return_sha256": review_sha,
        "human_rows_only_for_selected_owner": rows,
    }


def read_return_packet(path, owner_raw, csv_bytes, owner, originals):
    raw = read_owner_file(path, MAX_MANIFEST)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite owner reply"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise Hold("PRIVATE HOLD: unreadable original HUMAN owner reply") from exc
    if (type(doc) is not dict or set(doc) != RETURN_KEYS or
        doc["schema"] != REPLY_SCHEMA or
        not literal_false_authority(doc["authority"], FLAGS) or
        doc["historical_only"] is not True or
        any(doc[k] is not False for k in (
            "sources_reopened", "recipient_authenticated", "consent_assumed",
            "actions_dispatched", "appointments_booked", "verified_remediation"
        )) or doc["proposed_human_owner_label"] != owner or
        doc["original_owner_packet_sha256"] != digest(owner_raw) or
        doc["original_reply_csv_sha256"] != digest(csv_bytes) or
        raw != canonical(doc)):
        reject("PRIVATE HOLD: original HUMAN owner reply is not exact-source-bound")
    expected = read_reply_csv(csv_bytes, originals, digest(owner_raw))
    if doc["human_reply_rows"] != expected:
        reject("PRIVATE HOLD: original HUMAN reply rows do not match exact original CSV")
    source = json.loads(owner_raw.decode("utf-8"))
    for key in (
        "original_source_portfolio_sha256", "original_source_meeting_sha256",
        "original_review_return_sha256",
    ):
        if doc[key] != source[key]:
            reject("PRIVATE HOLD: recipient response claims different original context")
    return raw, expected


def read_originals(args):
    source = read_portfolio(args.portfolio)
    meeting_raw, meeting, entries = read_focus(args.meeting, source)
    review_raw, review_rows = read_return(
        args.review_return, digest(source[0]), digest(meeting_raw),
        meeting["original_case_contexts"], entries,
    )
    return source, meeting_raw, meeting, entries, review_raw, review_rows


def take(args):
    selected = [args.owner_packet, args.owner_reply, args.reply_csv]
    if (not 1 <= len(args.owner_packet) <= MAX_OWNERS or
        len(args.owner_reply) != len(args.owner_packet) or
        len(args.reply_csv) != len(args.owner_packet)):
        reject("PRIVATE HOLD: 1–8 full owner packet/reply/original CSV triples required")
    flat = [args.portfolio, args.meeting, args.review_return,
            args.private_parent] + [p for group in selected for p in group]
    if any(not local_path(p) for p in flat) or len(set(flat)) != len(flat):
        reject("PRIVATE HOLD: original source paths must be distinct canonical absolute")
    private_parent(args.private_parent)
    source, meeting_raw, meeting, entries, review_raw, reviewed = read_originals(args)
    source_sha, meeting_sha, review_sha = digest(source[0]), digest(meeting_raw), digest(review_raw)
    packets, owners, keys = [], set(), set()
    for packet_path, reply_path, csv_path in zip(*selected):
        owner_raw, owner, original_rows = read_owner_packet(packet_path)
        name = owner["proposed_human_owner_label"]
        if name in owners:
            reject("PRIVATE HOLD: duplicate proposed HUMAN owner within inbound workrooms")
        owners.add(name)
        if (meeting["proposed_human_owner_filter"] is not None and
            name != meeting["proposed_human_owner_filter"]):
            reject("PRIVATE HOLD: cannot widen original owner-scoped meeting")
        expected_rows = match_owners([name], entries, reviewed)[0]
        expected = canonical(expected_original_packet(name, expected_rows,
                                                     source_sha, meeting_sha, review_sha))
        if owner_raw != expected or original_rows != expected_rows:
            reject("PRIVATE HOLD: received owner packet differs from original source chain")
        csv_raw = read_owner_file(csv_path, MAX_MANIFEST)
        return_raw, decisions = read_return_packet(
            reply_path, owner_raw, csv_raw, name, original_rows
        )
        proposals = []
        for original, decision in zip(original_rows, decisions):
            identity = (original["local_case"], original["historical_transition"],
                        original["original_kit"])
            if identity in keys:
                reject("PRIVATE HOLD: conflicting original HUMAN source slot in inbox")
            keys.add(identity)
            proposals.append({
                "local_case": identity[0],
                "historical_transition": identity[1],
                "original_kit": identity[2],
                "original_proposed_human_owner": name,
                "original_human_priority": original["original_human_priority"],
                "original_human_stage": original["human_review_stage"],
                "new_human_reply_stage": decision["human_reply_stage"],
                "private_human_reply_text": decision["private_reply_note"],
            })
        packets.append({
            "owner_label": name,
            "original_owner_packet_sha256": digest(owner_raw),
            "original_owner_reply_sha256": digest(return_raw),
            "original_reply_csv_sha256": digest(csv_raw),
            "human_rows": proposals,
        })
    # Second source-read immediately before any output: historical originals
    # plus every selected owner packet/reply/CSV must remain byte-identical.
    replay = read_originals(args)
    if (replay[0][0] != source[0] or replay[1] != meeting_raw or
        replay[4] != review_raw):
        reject("PRIVATE HOLD: original HUMAN portfolio or meeting context drift")
    for packet, packet_path, reply_path, csv_path in zip(
        packets, args.owner_packet, args.owner_reply, args.reply_csv
    ):
        if (digest(read_owner_packet(packet_path)[0]) !=
            packet["original_owner_packet_sha256"] or
            digest(read_owner_file(reply_path, MAX_MANIFEST)) !=
            packet["original_owner_reply_sha256"] or
            digest(read_owner_file(csv_path, MAX_MANIFEST)) !=
            packet["original_reply_csv_sha256"]):
            reject("PRIVATE HOLD: owner source changed before inbox")
    return source_sha, meeting_sha, review_sha, packets


def source_free_html(packets):
    total = sum(len(p["human_rows"]) for p in packets)
    counts = Counter(row["new_human_reply_stage"] for packet in packets
                     for row in packet["human_rows"])
    body = [
        "<p><strong>PRIVATE source-minimal HUMAN inbox receipt.</strong> "
        "This is local historical proposed human text only, not an "
        "authenticated recipient or trusted authority. No client/target "
        "source reopened, grant, scope consent, scan, real dispatch, "
        "meeting appointment, finding or remediation verified.</p>",
        "<p>Distinct unsigned HUMAN packets: " + str(len(packets)) +
        "; original proposed follow-up slots: " + str(total) + ".</p>",
        "<table><thead><tr><th>Human proposal stage</th><th>Count</th>"
        "</tr></thead><tbody>",
    ]
    for stage in REPLY_STAGES:
        body.append("<tr><td>" + html.escape(stage) + "</td><td>" +
                    str(counts[stage]) + "</td></tr>")
    body.append("</tbody></table><p>No original path, SHA, HUMAN identity "
                "label or freeform text is disclosed in this counts-only "
                "PRIVATE overview. No response was automatically transmitted.</p>")
    return html_page("LightUp PRIVATE HUMAN return inbox overview", "".join(body))


def detailed_html(packets):
    body = [
        "<p><strong>OWNER-PRIVATE proposed HUMAN collaboration inbox.</strong> "
        "No recipient has been authenticated, client data retested, "
        "permission issued or security progress verified. Everything below "
        "is the explicit original human-label-bound proposed response.</p>",
        "<table><thead><tr><th>Proposed HUMAN owner label</th>"
        "<th>Original case/transition/kit</th><th>Original HUMAN stage</th>"
        "<th>Returned HUMAN stage</th><th>PRIVATE HUMAN reply</th>"
        "</tr></thead><tbody>",
    ]
    for packet in packets:
        for row in packet["human_rows"]:
            body.append(
                "<tr><td>" + html.escape(packet["owner_label"], quote=True) +
                "</td><td>" + "/".join(str(row[k]) for k in (
                    "local_case", "historical_transition", "original_kit"
                )) + "</td><td>" +
                html.escape(row["original_human_stage"]) + "</td><td>" +
                html.escape(row["new_human_reply_stage"]) + "</td><td>" +
                html.escape(row["private_human_reply_text"], quote=True) +
                "</td></tr>"
            )
    body.append("</tbody></table><p>Discussions do not change the original "
                "authorized scope, current task status or verified findings.</p>")
    return html_page("LightUp PRIVATE unsigned HUMAN response reconciliation", "".join(body))


def original_csv(packets):
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(OUTPUT_COLUMNS)
    for packet in packets:
        for row in packet["human_rows"]:
            writer.writerow([row[c] for c in OUTPUT_COLUMNS])
    return out.getvalue()


def run(args):
    source_sha, meeting_sha, review_sha, packets = take(args)
    document = {
        "schema": SCHEMA,
        "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_portfolio_sha256": source_sha,
        "original_meeting_sha256": meeting_sha,
        "original_review_return_sha256": review_sha,
        "original_owner_reply_packets_in_explicit_human_order": packets,
    }
    outputs = {
        "OPEN-PRIVATE.html": source_free_html(packets),
        "PRIVATE-HUMAN-owner-inbox.html": detailed_html(packets),
        "PRIVATE-HUMAN-owner-inbox.csv": original_csv(packets),
        "PRIVATE-HUMAN-owner-inbox.json": canonical(document),
        "HUMAN-inbox-review-template.csv": inbox_review_template(
            packets, digest(canonical(document))
        ),
    }
    if any(len(raw if isinstance(raw, bytes) else raw.encode("utf-8")) >
           MAX_MANIFEST for raw in outputs.values()):
        reject("PRIVATE HOLD: original private HUMAN inbox exceeds bounded output")
    folder = new_private(args.private_parent)
    try:
        for name, raw in outputs.items():
            write_private(folder, name, raw)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: original HUMAN reply proposals collated locally, never applied")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(
        description="Offline source-exact original PRIVATE HUMAN owner inbox"
    )
    parser.add_argument("--portfolio", required=True)
    parser.add_argument("--meeting", required=True)
    parser.add_argument("--review-return", required=True)
    parser.add_argument("--owner-packet", action="append", required=True,
                        help="Original owner-private JSON; repeat 1–8 in matching order")
    parser.add_argument("--owner-reply", action="append", required=True,
                        help="Matching native original PRIVATE-HUMAN-owner-reply.json")
    parser.add_argument("--reply-csv", action="append", required=True,
                        help="Matching original human-edited 0600 reply CSV")
    parser.add_argument("--private-parent", required=True)
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original owner reply inbox rejected", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
