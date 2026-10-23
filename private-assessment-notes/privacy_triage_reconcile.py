#!/usr/bin/env python3
"""Offline multi-reviewer HUMAN sensitivity reconciliation without authorization.

Admits original completed source-bound review packets, shows disagreements,
and prepares a new BLANK review against the same original source bytes.
This tool does not authenticate reviewers, vote on safety, share data or scan.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import html
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile

from notes import Hold, file_new, private_directory, save_json
from privacy_triage import (
    SCHEMA as TRIAGE_SCHEMA, FALSE_FLAGS, STATUSES, TOPICS,
    completed_packet, default_rows, csv_bytes,
)
from privacy_triage_history import load_round
from privacy_triage_studio import render as editor

SCHEMA = "lightup.private_notes_human_sensitivity_reconciliation.v1"
MIN_REVIEWS = 2
MAX_REVIEWS = 8
COLUMNS = ("original_ordinal", "reviewer_slot", "human_status", "human_topics",
           "human_note_present", "status_disagreement", "topic_disagreement",
           "human_note_disagreement")


def read_reviews(original: str, reviews: list[str]):
    if not MIN_REVIEWS <= len(reviews) <= MAX_REVIEWS:
        raise Hold("HOLD: select 2–8 existing completed original HUMAN sensitivity reviews")
    names = [str(Path(name).absolute()) for name in reviews]
    if len(set(names)) != len(names):
        raise Hold("HOLD: one original review directory cannot represent multiple reviewers")
    sources, source_sha, decisions_sha = completed_packet(original)
    packets = [load_round(name, sources, source_sha, decisions_sha)
               for name in names]
    # Two real people can arrive at byte-identical local HUMAN decisions.
    # Keep each separately selected packet; explicitly flag exact copies rather
    # than claiming two independent authenticated reviewers or rejecting consensus.
    return sources, source_sha, decisions_sha, packets


def matrix(packets: list[dict]) -> tuple[list[dict], list[dict]]:
    output = []
    summaries = []
    count = len(packets[0]["rows"])
    for index in range(count):
        entries = [packet["rows"][index] for packet in packets]
        status_disagreement = len({x["review_status"] for x in entries}) > 1
        topic_disagreement = len({x["privacy_topics"] for x in entries}) > 1
        note_disagreement = len({x["human_followup"] for x in entries}) > 1
        for reviewer_index, row in enumerate(entries, start=1):
            output.append({
                "original_ordinal": index + 1,
                "reviewer_slot": reviewer_index,
                "human_status": row["review_status"],
                "human_topics": row["privacy_topics"],
                "human_note_present": bool(row["human_followup"]),
                "status_disagreement": status_disagreement,
                "topic_disagreement": topic_disagreement,
                "human_note_disagreement": note_disagreement,
            })
        summaries.append({
            "original_ordinal": index + 1,
            "reviewer_count": len(entries),
            "status_disagreement": status_disagreement,
            "topic_disagreement": topic_disagreement,
            "human_note_disagreement": note_disagreement,
            "human_action_needed": (status_disagreement or topic_disagreement or
                                    note_disagreement or
                                    any(x["review_status"] != "PENDING" for x in entries)),
            "any_withhold": any(x["review_status"] == "WITHHOLD" for x in entries),
            "any_review_required": any(x["review_status"] == "REVIEW_REQUIRED"
                                       for x in entries),
        })
    return output, summaries


def matrix_csv(records: list[dict]) -> bytes:
    file = io.StringIO(newline="")
    writer = csv.DictWriter(file, fieldnames=COLUMNS, lineterminator="\r\n")
    writer.writeheader()
    for row in records:
        writer.writerow({
            key: ("TRUE" if row[key] else "FALSE")
            if type(row[key]) is bool else row[key]
            for key in COLUMNS
        })
    return file.getvalue().encode("utf-8")


def private_page(records: list[dict], summaries: list[dict], reviewers: int) -> bytes:
    table = []
    for summary in summaries:
        ordinal = summary["original_ordinal"]
        subset = [x for x in records if x["original_ordinal"] == ordinal]
        rendered = []
        for row in subset:
            rendered.append(
                "<li>HUMAN slot " + str(row["reviewer_slot"]) + ": <strong>" +
                html.escape(row["human_status"]) + "</strong> · " +
                html.escape(row["human_topics"]) + " · PRIVATE note: " +
                ("present" if row["human_note_present"] else "blank") +
                "</li>"
            )
        flags = []
        if summary["status_disagreement"]:
            flags.append("Status disagreement")
        if summary["topic_disagreement"]:
            flags.append("Category disagreement")
        if summary["human_note_disagreement"]:
            flags.append("PRIVATE human-note difference (text hidden)")
        if summary["any_withhold"]:
            flags.append("At least one reviewer selected WITHHOLD")
        if not flags:
            flags.append("Literal HUMAN labels align (not a privacy verdict)")
        table.append(
            "<section class='entry'><h2>Original #" + str(ordinal) + "</h2>"
            "<p><strong>" + html.escape(" · ".join(flags)) + "</strong></p>"
            "<ul>" + "".join(rendered) + "</ul></section>"
        )
    conflict_count = sum(
        x["status_disagreement"] or x["topic_disagreement"] or
        x["human_note_disagreement"] for x in summaries
    )
    action_count = sum(x["human_action_needed"] for x in summaries)
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'">
<title>LightUp PRIVATE HUMAN sensitivity reconciliation</title>
<style>body{max-width:1060px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui;color:#19344b}
.warning{background:#fff0e8;border-left:5px solid #a74825;padding:16px}
.entry{border:1px solid #cfdae5;border-radius:12px;padding:15px;margin:15px 0;break-inside:avoid}
h1{font-size:2rem}h2{font-size:1.1rem}li{margin:4px 0}
a:focus-visible{outline:3px solid #d48d2e}
@media print{body{margin:0}.entry{border:1px solid #777}}</style>
<header><p class="warning"><b>PRIVATE · DRAFT/HOLD · HUMAN ONLY</b><br>
Reviewer slot numbers are manually selected, NOT authenticated identities.
Agreement, absence of a reported concern, lower WITHHOLD counts or any
reconciliation choice does not prove that secrets were removed, privacy has
been cleared, a real client approved, or sharing is authorized. No source,
masked notes, original filenames/byte hashes or free HUMAN note contents
are embedded in this printable page. Never publish this private packet.</p>
<h1>Original-bound HUMAN sensitivity reconciliation</h1>
<p>Manually selected HUMAN review packets: """ + str(reviewers) +
            """ · declared exact-copy reviewer CSV pairs are not independently authenticated. Never treat a source-identical review as extra confidence.
Original source positions: """ + str(len(summaries)) +
            """ · literal disagreement positions: """ + str(conflict_count) +
            """ · proposed conversation positions: """ + str(action_count) +
            """. No consensus is automatically adopted. All next-round HUMAN
proposals start at PENDING / UNKNOWN, not at a supposed PASS.</p></header><main>""" +
            "".join(table) + """</main><footer>Incubate M3/M7 PLAN/LAB ONLY.
No scan, model, grant, target, dispatch, upload, auth, retest or release.
Native original source-bound HUMAN finalization is independently required.
</footer></html>""").encode("utf-8")


def agenda_page(summaries: list[dict]) -> bytes:
    attention = [x for x in summaries if x["human_action_needed"]]
    rows = []
    for s in attention:
        parts = []
        for attr, label in (
            ("status_disagreement", "reviewer HUMAN status differs"),
            ("topic_disagreement", "reviewer categories differ"),
            ("human_note_disagreement", "HUMAN note text differs (withheld)"),
            ("any_withhold", "WITHHOLD proposed by at least one reviewer"),
            ("any_review_required", "REVIEW_REQUIRED proposed"),
        ):
            if s[attr]:
                parts.append(label)
        if not parts:
            parts = ["HUMAN local concern status only"]
        rows.append("<li><b>Original #" + str(s["original_ordinal"]) + "</b>: " +
                    html.escape("; ".join(parts)) + "</li>")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none'">
<title>LightUp PRIVATE sensitivity conversation</title><style>
body{max-width:800px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui}
aside{background:#fff0e8;border-left:5px solid #a54825;padding:1rem}
li{padding:.25rem}</style><h1>PRIVATE HUMAN conversation agenda</h1>
<aside><b>HOLD — no verified reviewer identities or privacy safety verdict.</b>
Only locally declared original ordinal labels, never source content or free
PRIVATE note text. Independent owner and privacy review remain required.</aside>
<p>Human discussion proposals: """ + str(len(attention)) + """ of """ +
            str(len(summaries)) + """ original positions.</p><ol>""" +
            "".join(rows) +
            """</ol><p>Local status and uncertainty are not consent,
security findings, release permission, or evidence that a concern was fixed.
All original source/custody and authorization gates remain intact.</p></html>""").encode("utf-8")


def links_page(reviewers: int, sources: int) -> bytes:
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none'">
<title>LightUp PRIVATE HUMAN reconciliation kit</title><style>
body{max-width:820px;margin:2rem auto;padding:1rem;font:17px/1.6 system-ui}
aside{background:#fff1e9;border-left:5px solid #b04b2d;padding:1rem}</style>
<h1>Original-bound PRIVATE HUMAN reconciliation</h1>
<aside><b>HOLD / REVIEW_ONLY — not a scan, clearance, grant or recipient
approval.</b> A HUMAN review packet is not proof of actual source identity,
independent review, privacy consent, remediation or safe disclosure.</aside>
<p>Declared reviewer slots: """ + str(reviewers) +
            """ · original positions: """ + str(sources) + """.</p><ul>
<li><a href="PRIVATE-HUMAN-reconciliation-studio.html">Interactive offline reviewer comparison and explicit next HUMAN review editor</a></li>
<li><a href="PRIVATE-HUMAN-reconciliation.html">Printable complete HUMAN reviewer matrix</a></li>
<li><a href="PRIVATE-HUMAN-reconciliation.csv">Owner-private complete reviewer matrix CSV</a></li>
<li><a href="PRIVATE-HUMAN-discussion.html">Minimum-necessary HUMAN disagreement agenda</a></li>
<li><a href="PRIVATE-HUMAN-reconciliation-bindings.json">Original unsigned source-bound review receipts</a></li>
<li><a href="PRIVATE-HUMAN-sensitivity-editor.html">Blank next HUMAN review browser editor</a></li>
<li><a href="PRIVATE-HUMAN-sensitivity-template.csv">Blank full source-bound HUMAN template</a></li>
<li><a href="PRIVATE-triage-bindings.json">Next HUMAN template source binding</a></li>
</ul><p>To continue, review the matrix, make independent HUMAN decisions
in the blank editor, export the complete PRIVATE HUMAN CSV, move it into a
0600 owner-private location, and call the existing unchanged native
<code>notes.py sensitivity-finalize --triage-kit THIS_FOLDER</code>
with the same original completed source packet. Nothing is pre-approved,
copied into the new draft, shared or sent. Always HOLD.</p></html>""").encode("utf-8")


def build(original: str, reviews: list[str], parent_string: str) -> int:
    parent = private_directory(parent_string)
    sources, manifest_sha, decisions_sha, packets = read_reviews(original, reviews)
    records, summaries = matrix(packets)
    identical_pairs = [
        [first + 1, second + 1]
        for first in range(len(packets))
        for second in range(first + 1, len(packets))
        if packets[first]["csv_sha256_unsigned"] == packets[second]["csv_sha256_unsigned"]
    ]
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-sensitivity-reconcile-", dir=parent))
    os.chmod(kit, 0o700)
    finished = False
    try:
        receipt = {
            "schema": SCHEMA,
            "claimed_status": "HOLD",
            "declared_reviewers_not_authenticated": True,
            "literal_agreement_not_privacy_clearance": True,
            "original_manifest_sha256_unsigned": manifest_sha,
            "original_human_csv_sha256_unsigned": decisions_sha,
            "original_count": len(sources),
            "identical_human_csv_slot_pairs_not_identity_evidence": identical_pairs,
            "manual_reviewers": [
                {"human_slot": slot,
                 "original_receipt_sha256_unsigned": item["receipt_sha256_unsigned"],
                 "original_complete_csv_sha256_unsigned": item["csv_sha256_unsigned"]}
                for slot, item in enumerate(packets, start=1)
            ],
            "disagreement_original_positions": [
                row["original_ordinal"] for row in summaries
                if row["status_disagreement"] or row["topic_disagreement"]
                or row["human_note_disagreement"]
            ],
            "conversation_original_positions": [
                row["original_ordinal"] for row in summaries if row["human_action_needed"]
            ],
            **{flag: False for flag in FALSE_FLAGS},
        }
        save_json(kit / "PRIVATE-HUMAN-reconciliation-bindings.json", receipt)
        file_new(kit / "PRIVATE-HUMAN-reconciliation.html",
                 private_page(records, summaries, len(packets)))
        from privacy_triage_reconcile_studio import render as reviewer_studio
        file_new(kit / "PRIVATE-HUMAN-reconciliation-studio.html",
                 reviewer_studio(sources, packets))
        file_new(kit / "PRIVATE-HUMAN-reconciliation.csv", matrix_csv(records))
        file_new(kit / "PRIVATE-HUMAN-discussion.html", agenda_page(summaries))
        # Same immutable original source-binding schema as the native existing
        # sensitivity-prepare. It remains independently re-admitted unchanged
        # by the ORIGINAL sensitivity-finalize; no new admission authority.
        save_json(kit / "PRIVATE-triage-bindings.json", {
            "schema": TRIAGE_SCHEMA,
            "claimed_status": "HOLD",
            "original_manifest_sha256_unsigned": manifest_sha,
            "original_human_csv_sha256_unsigned": decisions_sha,
            "sources": [
                {"ordinal": source["ordinal"],
                 "source_sha256_unsigned": source["source_sha256_unsigned"]}
                for source in sources
            ],
            **{flag: False for flag in FALSE_FLAGS},
        })
        blank = default_rows(sources)
        file_new(kit / "PRIVATE-HUMAN-sensitivity-template.csv", csv_bytes(blank))
        file_new(kit / "PRIVATE-HUMAN-sensitivity-editor.html", editor(blank))
        file_new(kit / "OPEN-PRIVATE.html", links_page(len(packets), len(sources)))
        finished = True
        print("REVIEW_ONLY: original-bound PRIVATE HUMAN reviewer reconciliation prepared")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not finished:
            shutil.rmtree(kit)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Original-bound HUMAN sensitivity reconciliation (2–8 PRIVATE reviews)")
    parser.add_argument("--completed-packet", required=True)
    parser.add_argument("--review", required=True, action="append")
    parser.add_argument("--private-parent", required=True)
    options = parser.parse_args()
    try:
        return build(options.completed_packet, options.review, options.private_parent)
    except (Hold, OSError, ValueError, KeyError, TypeError):
        print("HOLD: PRIVATE HUMAN reviewer reconciliation refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
