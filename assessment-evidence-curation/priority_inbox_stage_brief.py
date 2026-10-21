#!/usr/bin/env python3
"""Minimum-necessary PRIVATE HUMAN stage+priority offline briefing.

Never sends, schedules, authorizes, tests or alters original assessment data.
Only explicit HUMAN stage and one source-declared HUMAN priority are included.
Full original-source and saved inbox byte reopening is required before output.
"""
from __future__ import annotations

import argparse
import sys

from briefing import h, json_bytes, publish_new
from curate import Hold, digest
from priority_inbox import FINAL, RECEIPT_OUT, ensure_output_outside_inputs
from priority_inbox_open import reopen_expected
from priority_inbox_action_queue import admitted_rows, STAGES
from priority_reply import UNTRUSTED_FLAGS
from revision import private_frame

PRIORITIES = ("routine", "soon", "urgent")
BRIEF = "PRIVATE-HUMAN-stage-priority-brief.html"
COUNTS = "PRIVATE-HUMAN-stage-priority-counts.json"
RECEIPT = "PRIVATE-HUMAN-stage-priority-receipt.json"


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: original-source HUMAN stage/priority brief refused")


def build(source: str, manifest: str, worksheet: str, selection_receipt: str,
          selection: str, curated_packet: str, handoffs: list[str],
          replies: list[str], inbox: str, stage: str,
          priority: str) -> tuple[dict[str, bytes], int]:
    require(stage in dict(STAGES) and priority in PRIORITIES)
    original, total = reopen_expected(
        source, manifest, worksheet, selection_receipt, selection,
        curated_packet, handoffs, replies, inbox)
    original_csv = original[FINAL]
    subset = [
        row for row, row_stage in admitted_rows(original_csv, total)
        if row_stage == stage and row["original_human_priority"] == priority
    ]
    require(bool(subset))
    items = []
    for row in subset:
        def datum(label: str, key: str) -> str:
            return "<dt>" + h(label) + "</dt><dd><pre>" + h(row[key]) + "</pre></dd>"
        items.append(
            "<article><h2>Original selected ordinal #" + h(row["original_ordinal"]) +
            "</h2><dl>" +
            datum("Original source severity (self-reported, not verified)",
                  "source_reported_severity") +
            datum("Evidence reference count (no evidence content)", "evidence_reference_count") +
            datum("Original HUMAN question (PRIVATE)", "original_human_question") +
            datum("Recipient HUMAN reply (PRIVATE, unverified)", "recipient_human_reply") +
            datum("Proposed next HUMAN question (PRIVATE)", "recipient_human_next_question") +
            "</dl><p>HUMAN independent source review: __________. "
            "HUMAN next step: __________. Nothing sent, assigned or resolved.</p></article>"
        )
    report = private_frame(
        "PRIVATE HUMAN selected stage/priority handoff — no authority",
        "<header><h1>LightUp · PRIVATE HUMAN stage/priority review handoff</h1>"
        "<p class='notice'>REVIEW ONLY · original lab claims and HUMAN responses "
        "are UNVERIFIED. No client/operator authorization, finding verification, "
        "consent, actual recipient, scan, task assignment, remediation or "
        "outbound delivery is asserted.</p>"
        "<p>Only selected HUMAN stage <strong>" + h(stage) +
        "</strong> and original human priority <strong>" + h(priority) +
        "</strong> are present. Other private HUMAN priorities/stages and "
        "their questions/notes are excluded. This is an explicit operator "
        "selection, not an automated risk decision.</p>"
        "<p>No original run, target, finding ID, source hash, evidence body or "
        "client name is copied from original source; however HUMAN-entered "
        "questions and replies may still reveal client/recipient identity. "
        "Never disclose without separate current HUMAN authorization.</p>"
        "<p>Selected original ordinal count: " + str(len(subset)) +
        ". Entire original PRIVATE inbox was re-admitted byte-for-byte before "
        "this new private output. Source hashes are UNSIGNED.</p></header>" +
        "".join(items))
    counts = {
        "schema": "lightup.private_human_selected_stage_priority_counts.v1",
        "status": "REVIEW_ONLY",
        "human_stage": stage,
        "human_priority": priority,
        "selected_original_human_rows": len(subset),
        **UNTRUSTED_FLAGS,
    }
    receipt = {
        "schema": "lightup.private_human_selected_stage_priority_receipt.v1",
        "status": "REVIEW_ONLY",
        "original_private_inbox_receipt_sha256_unsigned": digest(original[RECEIPT_OUT]),
        "original_private_inbox_complete_csv_sha256_unsigned": digest(original_csv),
        "private_stage_priority_brief_sha256_unsigned": digest(report),
        "private_selected_counts_sha256_unsigned": digest(json_bytes(counts)),
        "human_stage": stage,
        "human_priority": priority,
        "selected_original_human_rows": len(subset),
        **UNTRUSTED_FLAGS,
    }
    return {BRIEF: report, COUNTS: json_bytes(counts),
            RECEIPT: json_bytes(receipt)}, len(subset)


def publish(source: str, manifest: str, worksheet: str,
            selection_receipt: str, selection: str, curated_packet: str,
            handoffs: list[str], replies: list[str], inbox: str,
            stage: str, priority: str, output: str) -> int:
    ensure_output_outside_inputs(output, [inbox, curated_packet, *handoffs])
    files, count = build(source, manifest, worksheet, selection_receipt,
                         selection, curated_packet, handoffs, replies,
                         inbox, stage, priority)
    publish_new(output, files)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare a single PRIVATE HUMAN stage/priority review packet")
    for name in ("source", "manifest", "worksheet", "selection-receipt",
                 "selection", "curated-packet", "private-inbox", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--returned-csv", action="append", required=True)
    parser.add_argument("--human-stage", choices=[key for key, _ in STAGES],
                        required=True)
    parser.add_argument("--human-priority", choices=PRIORITIES, required=True)
    args = parser.parse_args()
    try:
        count = publish(
            args.source, args.manifest, args.worksheet, args.selection_receipt,
            args.selection, args.curated_packet, args.private_handoff,
            args.returned_csv, args.private_inbox, args.human_stage,
            args.human_priority, args.output_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError):
        print("HOLD: full source-bound private HUMAN inbox or selected subset invalid; "
              "nothing published", file=sys.stderr)
        return 3
    print("PRIVATE stage/priority HUMAN handoff published for " + str(count) +
          " original ordinals; no contact, task dispatch, permission or verification.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
