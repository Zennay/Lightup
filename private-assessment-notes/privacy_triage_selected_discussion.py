#!/usr/bin/env python3
"""Strict offline receipt for the reviewer Studio's selected-only HUMAN CSV.

A locally selected discussion export cannot authorize sharing or replace the
original full source-bound HUMAN review. Native admission always reopens the
original completed packet and every original completed reviewer packet before
producing a new, exclusive 0700/0600 owner-private human conversation room.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import html
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

from notes import Hold, file_new, private_directory, private_input, save_json
from privacy_triage import FALSE_FLAGS
from privacy_triage_reconcile import matrix, read_reviews

SCHEMA = "lightup.private_notes_human_selected_discussion_receipt.v1"
HEADER = (
    "original_ordinal", "human_stage_disagreement",
    "human_topic_disagreement", "private_note_disagreement",
    "at_least_one_human_withhold", "at_least_one_human_review_required",
)
FLAG_FIELDS = (
    "status_disagreement", "topic_disagreement", "human_note_disagreement",
    "any_withhold", "any_review_required",
)
MAX_SOURCE_BYTES = 65536
MAX_ROWS = 12


def canonical_selection(raw: bytes) -> list[tuple[int, tuple[bool, ...]]]:
    """Require the actual browser CSV's exact bytes and field presentation.

    Noncanonical or reordered files must be consciously re-exported from the
    local original Studio; no inference of missing rows or silent normalization.
    """
    if not raw or len(raw) > MAX_SOURCE_BYTES or b"\x00" in raw:
        raise Hold("HOLD: PRIVATE HUMAN selected discussion CSV missing or oversized")
    try:
        decoded = raw.decode("utf-8", "strict")
        if not decoded.endswith("\r\n") or decoded.startswith("\ufeff"):
            raise ValueError("line endings")
        reader = csv.reader(io.StringIO(decoded, newline=""), strict=True)
        rows = list(reader)
        if not rows or rows[0] != list(HEADER) or not 1 <= len(rows)-1 <= MAX_ROWS:
            raise ValueError("header/size")
        parsed = []
        previous = 0
        for row in rows[1:]:
            if len(row) != len(HEADER):
                raise ValueError("column count")
            literal = row[0]
            if not literal.isascii() or not literal.isdecimal():
                raise ValueError("ordinal")
            ordinal = int(literal)
            if literal != str(ordinal) or ordinal <= previous or ordinal > MAX_ROWS:
                raise ValueError("original order")
            previous = ordinal
            if any(value not in ("TRUE", "FALSE") for value in row[1:]):
                raise ValueError("boolean")
            parsed.append((ordinal, tuple(item == "TRUE" for item in row[1:])))
        # Browser emits literal unquoted header and quoted string fields,
        # CRLF including the final line; compare the full exact byte grammar.
        lines = [",".join(HEADER)]
        for ordinal, flags in parsed:
            cells = [str(ordinal), *("TRUE" if flag else "FALSE" for flag in flags)]
            lines.append(",".join('"' + cell + '"' for cell in cells))
        if ("\r\n".join(lines) + "\r\n").encode("utf-8") != raw:
            raise ValueError("noncanonical source")
        return parsed
    except (UnicodeError, ValueError, csv.Error):
        raise Hold("HOLD: noncanonical or incomplete local HUMAN selected CSV") from None


def admit(original: str, reviews: list[str], selected_path: str):
    # Original native admission verifies owner-private custody, actual source
    # bindings, both completed CSVs, all original review receipts and counts.
    sources, manifest_sha, decisions_sha, packets = read_reviews(original, reviews)
    raw = private_input(selected_path, MAX_SOURCE_BYTES)
    selected = canonical_selection(raw)
    _, summaries = matrix(packets)
    for ordinal, flags in selected:
        if ordinal > len(summaries):
            raise Hold("HOLD: selected original ordinal is outside the original packet")
        expected = tuple(bool(summaries[ordinal-1][key]) for key in FLAG_FIELDS)
        if flags != expected:
            raise Hold("HOLD: local selected discussion flags diverge from ORIGINAL HUMAN reviews")
    return sources, manifest_sha, decisions_sha, packets, raw, selected


def page(selected: list[tuple[int, tuple[bool, ...]]], original_count: int,
         review_count: int, duplicate_count: int) -> bytes:
    rows = []
    reasons = (
        "Declared HUMAN stages differ", "Declared HUMAN categories differ",
        "PRIVATE HUMAN note contents differ (text withheld)",
        "At least one declared HUMAN WITHHOLD",
        "At least one declared HUMAN REVIEW_REQUIRED",
    )
    for ordinal, flags in selected:
        signals = [label for label, enabled in zip(reasons, flags) if enabled]
        # A locally selected agreement is not a clearance or approval.
        desc = "; ".join(signals) if signals else (
            "Manually selected literal agreement; no privacy safety verdict")
        rows.append("<li><b>Original #" + str(ordinal) + "</b> — " +
                    html.escape(desc) + "</li>")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN discussion receipt</title>
<style>body{font:16px/1.6 system-ui;max-width:850px;margin:2rem auto;padding:1rem;color:#20354b}
aside{border-left:5px solid #a94325;padding:1rem;background:#fff0e8}
li{margin:0.7rem 0;padding:0.4rem;border-bottom:1px solid #ccd}
@media print{body{margin:0;padding:0}.warning{border:1px solid #777}}</style>
<h1>PRIVATE HUMAN selected conversation</h1>
<aside class="warning"><strong>DRAFT/HOLD · HUMAN ONLY · NOT RELEASED.</strong>
This sheet displays only manually selected ORIGINAL ordinal numbers and
verified literal comparison flags against original PRIVATE completed HUMAN
review submissions. Neither reviewer identity nor actual client consent is
authenticated. It does not verify masking, privacy clearance, a security fix,
recipient authority, approval, or permission to share. Keep owner-private.</aside>
<p>Selected positions: """ + str(len(selected)) + """ of """ + str(original_count) +
            """. Original HUMAN packets: """ + str(review_count) +
            """. Byte-identical original HUMAN CSV slot pairs: """ +
            str(duplicate_count) + """. Identical content is NOT proof of
independently authenticated reviewers.</p><ol>""" + "".join(rows) +
            """</ol><footer>No original note text, free HUMAN note text,
source filenames, source SHA values, target identifiers or client information
is included in this HTML. No scan, network, model, upload, dispatch, grant,
remediation assertion, consent or release. Original full native HUMAN review
and all external authority checks remain required.</footer></html>""").encode("utf-8")


def landing() -> bytes:
    return ("""<!doctype html><html lang="en">
<meta charset="utf-8"><meta http-equiv="Content-Security-Policy"
content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none'">
<title>PRIVATE HUMAN discussion</title><h1>PRIVATE · DRAFT/HOLD</h1>
<p>This original-bound local room is not authorized for sharing or release.</p>
<ul><li><a href="PRIVATE-HUMAN-conversation.html">Printable selected HUMAN discussion</a></li>
<li><a href="PRIVATE-HUMAN-selected-discussion.csv">Exact selected local original CSV (private)</a></li>
<li><a href="PRIVATE-HUMAN-selected-receipt.json">Unsigned PRIVATE original custody receipt</a></li></ul>
<p>No authenticated identity, verified privacy clearance, scope grant, customer
consent, external recipient or assessment activation.</p></html>""").encode("utf-8")


def receipt_for(sources, manifest_sha, decisions_sha, packets, csv_raw,
                selected, identical) -> dict:
    receipt = {
        "schema": SCHEMA,
        "claimed_status": "HOLD",
        "human_only": True,
        "not_authenticated_reviewer_identity": True,
        "not_a_privacy_clearance": True,
        "original_count": len(sources),
        "selected_count": len(selected),
        "original_manifest_sha256_unsigned": manifest_sha,
        "original_human_csv_sha256_unsigned": decisions_sha,
        "selected_csv_sha256_unsigned": sha256(csv_raw).hexdigest(),
        "manual_review_original_receipts_sha256_unsigned": [
            packet["receipt_sha256_unsigned"] for packet in packets],
        "manual_review_csv_sha256_unsigned": [
            packet["csv_sha256_unsigned"] for packet in packets],
        "identical_content_human_slot_pairs": identical,
        "selected_original_ordinals": [row[0] for row in selected],
        **{flag: False for flag in FALSE_FLAGS},
    }
    return receipt


def create(original: str, reviews: list[str], selection: str, parent_string: str) -> int:
    # Admission is completed before creating any output directory.
    sources, manifest_sha, decisions_sha, packets, csv_raw, selected = admit(
        original, reviews, selection)
    identical = [
        [i+1, j+1]
        for i in range(len(packets))
        for j in range(i+1, len(packets))
        if packets[i]["csv_sha256_unsigned"] == packets[j]["csv_sha256_unsigned"]
    ]
    parent = private_directory(parent_string)
    room = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-discussion-", dir=parent))
    os.chmod(room, 0o700)
    finished = False
    try:
        receipt = receipt_for(sources, manifest_sha, decisions_sha, packets,
                              csv_raw, selected, identical)
        file_new(room / "PRIVATE-HUMAN-selected-discussion.csv", csv_raw)
        save_json(room / "PRIVATE-HUMAN-selected-receipt.json", receipt)
        file_new(room / "PRIVATE-HUMAN-conversation.html",
                 page(selected, len(sources), len(packets), len(identical)))
        file_new(room / "OPEN-PRIVATE.html", landing())
        finished = True
        print("HOLD: PRIVATE HUMAN selected discussion admitted; NEVER authorization")
        print("OPEN LOCALLY: " + str(room / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not finished:
            shutil.rmtree(room)



def reopen(original: str, reviews: list[str], room_name: str) -> int:
    """Read-only original-bound reopener, not an approval or a fix verdict."""
    room = private_directory(room_name)
    sources, manifest_sha, decisions_sha, packets, csv_raw, selected = admit(
        original, reviews, str(room / "PRIVATE-HUMAN-selected-discussion.csv"))
    identical = [
        [i+1, j+1]
        for i in range(len(packets))
        for j in range(i+1, len(packets))
        if packets[i]["csv_sha256_unsigned"] == packets[j]["csv_sha256_unsigned"]
    ]
    receipt = receipt_for(
        sources, manifest_sha, decisions_sha, packets, csv_raw, selected, identical)
    expected_receipt = (json.dumps(receipt, indent=2, sort_keys=True,
                                   ensure_ascii=False) + "\n").encode("utf-8")
    required = (
        ("PRIVATE-HUMAN-selected-receipt.json", expected_receipt),
        ("PRIVATE-HUMAN-conversation.html",
         page(selected, len(sources), len(packets), len(identical))),
        ("OPEN-PRIVATE.html", landing()),
    )
    for filename, expected in required:
        if private_input(str(room / filename), 65536) != expected:
            raise Hold("HOLD: previously received PRIVATE HUMAN packet is altered")
    print("HOLD: original PRIVATE HUMAN selected packet reopened with exact source/review/derived-byte bindings")
    print("OPEN LOCALLY: " + str(room / "OPEN-PRIVATE.html"))
    return 3


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Original-bound offline PRIVATE selected HUMAN discussion receipt")
    parser.add_argument("--completed-packet", required=True)
    parser.add_argument("--review", action="append", required=True)
    parser.add_argument("--selected-csv")
    parser.add_argument("--private-parent")
    parser.add_argument("--room", help="reopen a previously received owner-private room; read-only")
    args = parser.parse_args()
    try:
        if args.room:
            if args.selected_csv or args.private_parent:
                raise Hold("HOLD: reopen accepts only --room with original reviews")
            return reopen(args.completed_packet, args.review, args.room)
        if not args.selected_csv or not args.private_parent:
            raise Hold("HOLD: receive requires --selected-csv and --private-parent")
        return create(args.completed_packet, args.review, args.selected_csv, args.private_parent)
    except (Hold, OSError, ValueError, TypeError, KeyError):
        print("HOLD: PRIVATE selected HUMAN discussion admission refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
