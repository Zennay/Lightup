#!/usr/bin/env python3
"""Source-reopened PRIVATE HUMAN manual review CSV intake (REVIEW ONLY).

Never authenticates a reviewer or overrides real original source/recipient replies.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import io
import os
import stat
import sys

from curate import Hold, digest, human_text_ok
from briefing import h, json_bytes, publish_new
from human_return import read_limited_file
from priority_inbox import ensure_output_outside_inputs
from priority_inbox_continuity_docket import (
    CSV as DOCKET_CSV, RECEIPT as DOCKET_RECEIPT,
    LIMIT, build as build_docket, FILTERS,
    require_outside_aggregate_folder,
)
from priority_inbox_continuity_docket_open import reopen as reopen_docket
from priority_inbox_continuity_studio import CHOICES
from priority_reply import UNTRUSTED_FLAGS
from revision import private_frame

RETURN_HEADER = (
    "private_docket_csv_sha256_unsigned", "original_human_ordinal",
    "human_review_disposition", "human_review_note",
)
ALLOWED = dict(CHOICES)
REVIEW_CSV = "PRIVATE-HUMAN-original-review-return.csv"
REPORT = "PRIVATE-HUMAN-original-review-notes.html"
COUNTS = "PRIVATE-HUMAN-original-review-counts.json"
RECEIPT = "PRIVATE-HUMAN-original-review-receipt.json"
CAP = 256 * 1024


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: original-source PRIVATE HUMAN reviewer return invalid")


def read_return(raw: bytes, original_docket_csv: bytes) -> list[dict]:
    try:
        decoded = raw.decode("utf-8-sig")
        require("\x00" not in decoded and
                "\r" not in decoded.replace("\r\n", ""))
        reader = csv.reader(io.StringIO(decoded, newline=""), strict=True)
        require(tuple(next(reader)) == RETURN_HEADER)
        selected = list(csv.DictReader(
            io.StringIO(original_docket_csv.decode("utf-8"), newline=""),
            strict=True))
        require(0 < len(selected) <= 64)
        require(all("original_human_ordinal" in row and
                    "original_human_priority" in row and
                    "human_review_bucket_unverified" in row and
                    "latest_human_stage" in row for row in selected))
        rows = list(reader)
        require(len(rows) == len(selected))
        marker = digest(original_docket_csv)
        return_rows = []
        for pair, original in zip(rows, selected):
            require(len(pair) == len(RETURN_HEADER))
            binding, ordinal_raw, disposition, note = pair
            ordinal = int(ordinal_raw)
            require(binding == marker and ordinal_raw == str(ordinal) and
                    ordinal_raw == original["original_human_ordinal"] and
                    disposition in ALLOWED and len(note) <= 500 and
                    "\r" not in note and "\n" not in note and
                    "\t" not in note and human_text_ok(note))
            return_rows.append({
                "ordinal": ordinal,
                "priority": original["original_human_priority"],
                "bucket": original["human_review_bucket_unverified"],
                "latest_stage": original["latest_human_stage"],
                "disposition": disposition, "note": note,
            })
        return return_rows
    except (ValueError, TypeError, KeyError, UnicodeError, csv.Error,
            OverflowError, MemoryError):
        raise Hold("HOLD: PRIVATE HUMAN review CSV incomplete or incorrect") from None


def build(source: str, manifest: str, worksheet: str, selection_receipt: str,
          selection: str, curated: str, handoffs: list[str],
          replies: list[list[str]], inboxes: list[str], filter_mode: str,
          ordinals: list[int], saved_docket: str, human_return_csv: str
          ) -> tuple[dict[str, bytes], int]:
    # Independent full original source/custody readmission, including all
    # original HUMAN rounds. Do not trust the downloaded CSV anchor alone.
    count = reopen_docket(source, manifest, worksheet, selection_receipt,
                          selection, curated, handoffs, replies, inboxes,
                          filter_mode, ordinals, saved_docket)
    expected, _ = build_docket(source, manifest, worksheet, selection_receipt,
                               selection, curated, handoffs, replies, inboxes,
                               filter_mode, ordinals)
    require(count > 0 and count <= 64)
    original_csv = expected[DOCKET_CSV]
    raw = read_limited_file(human_return_csv, CAP)
    reviews = read_return(raw, original_csv)
    require(len(reviews) == count)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(RETURN_HEADER)
    original_marker = digest(original_csv)
    for row in reviews:
        writer.writerow((
            original_marker, row["ordinal"], row["disposition"], row["note"]))
    normalized = output.getvalue().encode("utf-8")
    groups = Counter(row["disposition"] for row in reviews)
    cards = "".join(
        "<article><h2>Original HUMAN ordinal #" + str(row["ordinal"]) +
        " · " + h(row["priority"]) + "</h2><p>Previous human review "
        "category: " + h(row["bucket"]) + " · latest HUMAN stage: " +
        h(row["latest_stage"]) + "</p><p>New HUMAN disposition "
        "(unverified): <strong>" + h(ALLOWED[row["disposition"]]) +
        "</strong></p><h3>New PRIVATE HUMAN review note</h3><pre>" +
        h(row["note"] or "(none)") +
        "</pre><p>Independent verification: __________ · HUMAN follow-up: "
        "__________</p></article>"
        for row in reviews)
    html = private_frame(
        "PRIVATE HUMAN source-bound review-return notes",
        "<header><h1>LightUp · PRIVATE original HUMAN review-return notes</h1>"
        "<p class='notice'>REVIEW ONLY. Previous source/selection, complete "
        "PRIVATE docket, every original HUMAN return, and manual reviewer CSV "
        "were checked for exact local consistency. Nothing authenticates "
        "HUMAN reviewer identity, real chronology, client/operator consent, "
        "finding validity or remediation. No authorization, message, task "
        "dispatch, assessment or original-source edit.</p>"
        "<p>This PRIVATE owner-only document contains new HUMAN-entered notes "
        "and selected original ordinals, but no original target, question, "
        "evidence body, client identity or original recipient reply. Source "
        "details stay in the separately saved original PRIVATE dossier. "
        "Review disposition is a HUMAN draft, not closure or permission to "
        "contact any recipient.</p></header>" + cards)
    summary = {
        "schema": "lightup.private_human_source_bound_review_return.v1",
        "status": "REVIEW_ONLY",
        "source_bound_original_docket_review_count": count,
        "human_review_disposition_counts": dict(sorted(groups.items())),
        "human_reviewer_identity_verified": False,
        "reviewer_approval_authenticated": False,
        **UNTRUSTED_FLAGS,
    }
    count_raw = json_bytes(summary)
    receipt = {
        "schema": "lightup.private_human_source_bound_review_return_receipt.v1",
        "status": "REVIEW_ONLY",
        "original_private_docket_receipt_sha256_unsigned":
            digest(expected[DOCKET_RECEIPT]),
        "original_private_docket_csv_sha256_unsigned": original_marker,
        "operator_entered_original_csv_sha256_unsigned": digest(raw),
        "private_normalized_return_sha256_unsigned": digest(normalized),
        "private_review_html_sha256_unsigned": digest(html),
        "private_counts_sha256_unsigned": digest(count_raw),
        "selected_original_human_ordinals": [r["ordinal"] for r in reviews],
        **UNTRUSTED_FLAGS,
    }
    files = {REVIEW_CSV: normalized, REPORT: html, COUNTS: count_raw,
             RECEIPT: json_bytes(receipt)}
    require(all(0 < len(content) <= LIMIT for content in files.values()))
    return files, count


def publish(*args) -> int:
    (*sources, output_dir) = args
    require_outside_aggregate_folder(output_dir)
    ensure_output_outside_inputs(
        output_dir, [sources[5], *sources[6], *sources[8], sources[11]])
    files, count = build(*sources)
    publish_new(output_dir, files)
    return count


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Admit local PRIVATE HUMAN reviewer notes against all original source-bound rounds")
    for key in ("source", "manifest", "worksheet", "selection-receipt",
                "selection", "curated-packet", "private-docket-dir",
                "review-returned-csv", "output-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--round-inbox", action="append", required=True)
    parser.add_argument("--round-returned-csv", action="append", required=True)
    parser.add_argument("--filter", choices=FILTERS, default="attention")
    parser.add_argument("--human-ordinal", action="append", type=int)
    return parser.parse_args()


def main() -> int:
    a = arguments()
    try:
        rounds, groups = len(a.round_inbox), len(a.private_handoff)
        require(2 <= rounds <= 8 and 1 <= groups <= 3 and
                len(a.round_returned_csv) == rounds * groups)
        replies = [a.round_returned_csv[i:i + groups]
                   for i in range(0, rounds * groups, groups)]
        count = publish(
            a.source, a.manifest, a.worksheet, a.selection_receipt,
            a.selection, a.curated_packet, a.private_handoff, replies,
            a.round_inbox, a.filter, a.human_ordinal or [],
            a.private_docket_dir, a.review_returned_csv, a.output_dir)
    except (Hold, OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, MemoryError, RecursionError, csv.Error):
        print("HOLD: original-source HUMAN review return refused; no file published",
              file=sys.stderr)
        return 3
    print("PRIVATE source-bound HUMAN review notes prepared for " +
          str(count) + " selected original HUMAN rows; REVIEW ONLY, no authority.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
