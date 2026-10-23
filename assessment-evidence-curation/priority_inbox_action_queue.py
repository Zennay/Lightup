#!/usr/bin/env python3
"""Source-exact, script-free HUMAN action queue for an existing PRIVATE inbox.

Independent companion: reopening the ORIGINAL inbox requires the identical
source, all original priority handoffs and returned HUMAN CSVs. Missing or
modified sources HOLD. No scheduling, messages, target calls or authorization.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import io
import sys

from briefing import h, json_bytes, publish_new
from curate import Hold, digest
from priority_inbox import FINAL, RECEIPT_OUT, ensure_output_outside_inputs
from priority_inbox_open import reopen_expected
from priority_reply import UNTRUSTED_FLAGS
from response import HEADER
from revision import private_frame

QUEUE = "PRIVATE-HUMAN-action-queue.html"
COUNTS = "PRIVATE-HUMAN-action-queue-counts.json"
RECEIPT = "PRIVATE-HUMAN-action-queue-receipt.json"
STAGES = (
    ("blocked_human", "HUMAN blocked — explicit discussion required"),
    ("needs_more_information", "HUMAN follow-up questions required"),
    ("no_human_response", "HUMAN response not received"),
    ("responded_claimed", "HUMAN response claimed — independently review"),
)


def require(value: bool) -> None:
    if not value:
        raise Hold("HOLD: original-source HUMAN action queue input changed")



def admitted_rows(raw: bytes, count: int) -> list[tuple[dict, str]]:
    """Parse the already native-original-admitted HUMAN unified CSV."""
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""),
                            strict=True)
    require(reader.fieldnames == list(HEADER))
    rows = list(reader)
    require(len(rows) == count and 1 <= count <= 64)
    safe_rows = []
    previous = 0
    for row in rows:
        require(type(row) is dict and None not in row and
                set(row) == set(HEADER))
        ordinal = int(row["original_ordinal"])
        require(str(ordinal) == row["original_ordinal"] and
                previous < ordinal and ordinal > 0)
        previous = ordinal
        stage = row["recipient_reported_stage"] or "no_human_response"
        require(stage in dict(STAGES))
        safe_rows.append((row, stage))

    return safe_rows


def build(source: str, manifest: str, worksheet: str, selection_receipt: str,
          selection: str, curated_packet: str, handoffs: list[str],
          replies: list[str], inbox: str) -> tuple[dict[str, bytes], int]:
    original, count = reopen_expected(
        source, manifest, worksheet, selection_receipt, selection,
        curated_packet, handoffs, replies, inbox)
    # The original native module has already admitted this complete CSV
    # from the original source and all source-bound HUMAN returns.
    raw = original[FINAL]
    safe_rows = admitted_rows(raw, count)

    navigation = []
    sections = []
    stage_counts = Counter(stage for _, stage in safe_rows)
    priority_counts: dict[str, dict[str, int]] = {}
    for key, label in STAGES:
        group = [(r, s) for r, s in safe_rows if s == key]
        navigation.append("<a href='#stage-" + h(key) + "'>" + h(label) +
                          " (" + str(len(group)) + ")</a>")
        cards = []
        for row, _ in group:
            priority = row["original_human_priority"]
            group_counts = priority_counts.setdefault(priority, {})
            group_counts[key] = group_counts.get(key, 0) + 1
            def cell(name: str, value: str) -> str:
                return "<dt>" + h(name) + "</dt><dd><pre>" + h(value) + "</pre></dd>"
            cards.append(
                "<article id='source-ordinal-" + h(row["original_ordinal"]) + "'>"
                "<h3>Original selected ordinal #" + h(row["original_ordinal"]) + "</h3><dl>" +
                cell("Source-reported severity (UNVERIFIED)", row["source_reported_severity"]) +
                cell("Source evidence references (count only)", row["evidence_reference_count"]) +
                cell("HUMAN selected priority (UNVERIFIED)", priority) +
                cell("Original HUMAN question (PRIVATE)", row["original_human_question"]) +
                cell("Recipient self-reported stage", key) +
                cell("HUMAN reply (PRIVATE, UNVERIFIED)", row["recipient_human_reply"]) +
                cell("Next HUMAN question (PRIVATE)", row["recipient_human_next_question"]) +
                "</dl><p>HUMAN independent reviewer: __________ &nbsp; "
                "HUMAN next step: __________</p></article>"
            )
        sections.append(
            "<section id='stage-" + h(key) + "'><h2>" + h(label) +
            " · " + str(len(cards)) + "</h2>" + "".join(cards) + "</section>")
    html = private_frame(
        "PRIVATE original-source HUMAN action queue — REVIEW ONLY",
        "<header><h1>LightUp · PRIVATE HUMAN response action queue</h1>"
        "<p class='notice'>REVIEW ONLY · no verified finding, remediation, "
        "recipient identity, consent, authorization, grant, scan, action "
        "dispatch or booking. HUMAN reports can be incomplete or false.</p>"
        "<p>Original source, briefing, worksheet, selection, every nonempty "
        "priority handoff and HUMAN response were re-admitted. The saved "
        "PRIVATE inbox was byte-reopened before producing this new document. "
        "No inputs were modified.</p>"
        "<p>No original target, run ID, finding ID, URL, evidence body, "
        "customer label or original source hash is copied into this view. "
        "Questions and replies may STILL identify confidential customers: "
        "owner-private only; separately verify current disclosure authority.</p>"
        "<p>Rows: " + str(count) + ". A blank answer is NOT a fixed issue. "
        "Group order is an operator convenience, not a calculated severity "
        "or independently verified triage.</p>"
        "<nav aria-label='Unverified HUMAN stage groups'>" +
        " · ".join(navigation) + "</nav></header>" + "".join(sections))
    counts = {
        "schema": "lightup.private_human_action_queue_counts.v1",
        "status": "REVIEW_ONLY",
        "selected_human_count": count,
        "human_stage_counts": {name: stage_counts[name] for name, _ in STAGES},
        "human_priority_stage_counts": {
            priority: {name: values.get(name, 0) for name, _ in STAGES}
            for priority, values in sorted(priority_counts.items())
        },
        **UNTRUSTED_FLAGS,
    }
    receipt = {
        "schema": "lightup.private_human_action_queue_receipt.v1",
        "status": "REVIEW_ONLY",
        "original_private_inbox_receipt_sha256_unsigned": digest(original[RECEIPT_OUT]),
        "original_private_inbox_complete_csv_sha256_unsigned": digest(raw),
        "private_action_queue_sha256_unsigned": digest(html),
        "private_counts_sha256_unsigned": digest(json_bytes(counts)),
        "selected_human_count": count,
        **UNTRUSTED_FLAGS,
    }
    return {QUEUE: html, COUNTS: json_bytes(counts),
            RECEIPT: json_bytes(receipt)}, count



def publish_queue(source: str, manifest: str, worksheet: str,
                  selection_receipt: str, selection: str, curated_packet: str,
                  handoffs: list[str], replies: list[str],
                  inbox: str, output: str) -> int:
    ensure_output_outside_inputs(output, [
        curated_packet, inbox, *handoffs])
    files, count = build(source, manifest, worksheet, selection_receipt,
                         selection, curated_packet, handoffs, replies, inbox)
    publish_new(output, files)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an offline PRIVATE source-exact HUMAN action queue; no authority")
    for name in ("source", "manifest", "worksheet", "selection-receipt",
                 "selection", "curated-packet", "private-inbox", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--returned-csv", action="append", required=True)
    args = parser.parse_args()
    try:
        count = publish_queue(
            args.source, args.manifest, args.worksheet, args.selection_receipt,
            args.selection, args.curated_packet, args.private_handoff,
            args.returned_csv, args.private_inbox, args.output_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError, csv.Error):
        print("HOLD: original private inbox/source/queue admission refused; "
              "no existing outputs changed", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN stage action queue published for " + str(count) +
          " source-selected rows; REVIEW_ONLY, not authorization or task dispatch.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
