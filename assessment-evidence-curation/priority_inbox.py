#!/usr/bin/env python3
"""Reconcile separately received PRIVATE HUMAN priority replies into one ORIGINAL CSV.

All sources and original selection membership re-admitted; requires the complete
set of nonempty priority groups, with no duplicate or implied HUMAN reply.
No original evidence target is exported, authenticated, retested or acted upon.
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import sys

from curate import Hold, digest
from briefing import h, json_bytes, publish_new
from human_return import read_limited_file
from packet_open import json_private, reopen as reopen_curated
from packet_handoff import RECEIPT, TEMPLATE, reopen as reopen_handoff
from priority_reconcile import read_owner_dir
from priority_reply import admit_rows, MAX_RETURN_BYTES, UNTRUSTED_FLAGS
from response import (HEADER, STAGES, accepted_original, csv_template,
                      admit_returned_reply)
from revision import private_frame

FINAL = "PRIVATE-original-HUMAN-unified-response.csv"
DETAIL = "PRIVATE-original-HUMAN-answer-inbox.html"
REPORT = "PRIVATE-original-HUMAN-priority-inbox.html"
COUNTS = "PRIVATE-original-HUMAN-priority-inbox-counts.json"
RECEIPT_OUT = "PRIVATE-original-HUMAN-priority-inbox-receipt.json"


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: PRIVATE original HUMAN priority inbox refused")


def ensure_output_outside_inputs(output: str, protected_dirs: list[str]) -> None:
    destination = os.path.realpath(os.path.abspath(output))
    for item in protected_dirs:
        source_dir = os.path.realpath(os.path.abspath(item))
        try:
            overlap = os.path.commonpath((destination, source_dir))
        except ValueError:
            continue
        require(overlap != source_dir)


def build(source_path: str, manifest_path: str, worksheet_path: str,
          selection_receipt: str, selection_path: str, curated_dir: str,
          handoff_paths: list[str], reply_paths: list[str]) -> tuple[dict[str, bytes], int]:
    require(len(handoff_paths) == len(reply_paths) and 1 <= len(handoff_paths) <= 3)
    source, source_sha, worksheet_sha, original_selection, selected = accepted_original(
        source_path, manifest_path, worksheet_path, selection_receipt, selection_path)
    reopen_curated(curated_dir)
    full_raw = read_owner_dir(curated_dir, ("PRIVATE-curation-receipt.json",))[
        "PRIVATE-curation-receipt.json"
    ]
    full = json_private(full_raw)
    require(full["original_source_sha256_unsigned"] == source_sha and
            full["human_worksheet_sha256_unsigned"] == worksheet_sha and
            full["human_selection_sha256_unsigned"] == digest(original_selection) and
            full["selected_original_ordinals"] == [row["ordinal"] for row in selected])
    groups = {row["priority"] for row in selected}
    require(len(groups) == len(handoff_paths))

    seen: set[str] = set()
    answers: dict[int, dict] = {}
    receipts: dict[str, dict] = {}
    for handoff_path, reply_path in zip(handoff_paths, reply_paths):
        amount = reopen_handoff(handoff_path)
        bundle = read_owner_dir(handoff_path, (RECEIPT, TEMPLATE))
        receipt_raw = bundle[RECEIPT]
        handoff = json_private(receipt_raw)
        require(handoff["original_private_packet_receipt_sha256_unsigned"] ==
                digest(full_raw))
        priority = handoff["source_human_priority"]
        require(priority in groups and priority not in seen)
        seen.add(priority)
        subset = [row for row in selected if row["priority"] == priority]
        require(len(subset) == amount and
                bundle[TEMPLATE] == csv_template(source, subset))
        incoming = read_limited_file(reply_path, MAX_RETURN_BYTES)
        records = admit_rows(bundle[TEMPLATE], incoming)
        require(len(records) == amount)
        for row in records:
            ordinal = int(row["ordinal"])
            require(ordinal not in answers and row["human_priority"] == priority)
            answers[ordinal] = row
        receipts[priority] = {
            "original_handoff_receipt_sha256_unsigned": digest(receipt_raw),
            "human_returned_csv_sha256_unsigned": digest(incoming),
            "received_human_row_count": amount,
        }
    require(seen == groups and len(answers) == len(selected))

    # Full ORIGINAL recipient CSV, all selected ordinals in original source order.
    # A recipient's empty claim remains an EXPLICIT blank, never an asserted fix.
    document = io.StringIO(newline="")
    writer = csv.writer(document, lineterminator="\r\n")
    writer.writerow(HEADER)
    for item in selected:
        ordinal = item["ordinal"]
        human = answers[ordinal]
        finding = source["findings"][ordinal - 1]
        stage = ("" if human["recipient_stage"] == "no_human_response"
                 else human["recipient_stage"])
        writer.writerow((ordinal, finding["severity"], len(finding["evidence_ids"]),
                         item["priority"], item["question"], stage,
                         human["recipient_reply"], human["recipient_next_question"]))
    combined = document.getvalue().encode("utf-8")
    require(len(combined) <= MAX_RETURN_BYTES)
    # Independently use ORIGINAL native complete selected-row response parser.
    original_response = admit_returned_reply(combined, source, selected)
    require(len(original_response) == len(selected))

    stage_count = {
        name or "no_human_response":
            sum(x["recipient_stage"] == (name or "no_human_response")
                for x in answers.values())
        for name in STAGES
    }
    per_group = {
        priority: {
            "selected_human_count": sum(x["priority"] == priority for x in selected),
            "human_response_stage_counts": {
                name or "no_human_response":
                    sum(x["human_priority"] == priority and
                        x["recipient_stage"] == (name or "no_human_response")
                        for x in answers.values())
                for name in STAGES
            },
        } for priority in sorted(groups)
    }
    fragment = "".join(
        "<article><h2>HUMAN priority: " + h(priority) + "</h2><p>Original "
        "selected questions: " + str(items["selected_human_count"]) +
        ". Claimed responses: " +
        str(items["human_response_stage_counts"]["responded_claimed"]) +
        "; HUMAN follow-up needed: " +
        str(items["human_response_stage_counts"]["needs_more_information"]) +
        "; HUMAN blocked: " +
        str(items["human_response_stage_counts"]["blocked_human"]) +
        "; no human answer: " +
        str(items["human_response_stage_counts"]["no_human_response"]) +
        ".</p></article>" for priority, items in per_group.items()
    )
    report = private_frame(
        "PRIVATE original source HUMAN priority inbox",
        "<header><h1>LightUp · PRIVATE original-source HUMAN reply inbox</h1>"
        "<p class='notice'>REVIEW ONLY — separate unverified HUMAN statements "
        "combined into ONE exact original source-row CSV. This is NOT a scan, "
        "authenticated human, verified finding, fix, consent, or authorization.</p>"
        "<p>Entire original lab source/manifest/worksheet/selection and every "
        "PRIVATE priority handoff were strictly readmitted. Every declared "
        "nonempty HUMAN group must be included exactly once. No original "
        "target/evidence content appears in this stage-count-only report.</p>"
        "<p>HUMAN questions in the separately generated complete PRIVATE CSV "
        "may STILL disclose clients. Independent current disclosure review and "
        "original HUMAN native response finalization remain required.</p>"
        "<p>Original source finding count: " + str(len(source["findings"])) +
        "; HUMAN selected count: " + str(len(selected)) + ".</p></header>" + fragment
    )
    from priority_inbox_detail import render as render_detail
    private_answer_inbox = render_detail(source, selected, answers)
    counts = {
        "schema": "lightup.private_original_human_priority_inbox_counts.v1",
        "status": "REVIEW_ONLY",
        "original_source_reported_findings": len(source["findings"]),
        "selected_human_count": len(selected),
        "human_priority_group_count": len(groups),
        "recipient_stage_counts": stage_count,
        "human_priority_stage_counts": per_group,
        **UNTRUSTED_FLAGS,
    }
    receipt = {
        "schema": "lightup.private_original_human_priority_inbox.v1",
        "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": source_sha,
        "original_worksheet_sha256_unsigned": worksheet_sha,
        "original_selection_sha256_unsigned": digest(original_selection),
        "original_curated_packet_receipt_sha256_unsigned": digest(full_raw),
        "per_human_priority_unsigned_receipts": receipts,
        "private_unified_response_sha256_unsigned": digest(combined),
        "private_detailed_inbox_sha256_unsigned": digest(private_answer_inbox),
        "private_report_sha256_unsigned": digest(report),
        "private_counts_sha256_unsigned": digest(json_bytes(counts)),
        "human_selected_count": len(selected),
        **UNTRUSTED_FLAGS,
    }
    return ({
        FINAL: combined, REPORT: report, DETAIL: private_answer_inbox,
        COUNTS: json_bytes(counts), RECEIPT_OUT: json_bytes(receipt),
    }, len(selected))


def join(source_path: str, manifest_path: str, worksheet_path: str,
         selection_receipt: str, selection_path: str, curated_dir: str,
         handoff_paths: list[str], reply_paths: list[str], output: str) -> int:
    ensure_output_outside_inputs(output, [curated_dir, *handoff_paths])
    files, count = build(source_path, manifest_path, worksheet_path,
                         selection_receipt, selection_path, curated_dir,
                         handoff_paths, reply_paths)
    publish_new(output, files)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate ALL original priority-human returns offline; never grants authorization")
    for key in ("source", "manifest", "worksheet", "selection-receipt",
                "selection", "curated-packet", "output-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True,
                        help="one for each nonempty original HUMAN priority group")
    parser.add_argument("--returned-csv", action="append", required=True,
                        help="corresponding original HUMAN priority reply CSV")
    args = parser.parse_args()
    try:
        amount = join(args.source, args.manifest, args.worksheet,
                      args.selection_receipt, args.selection, args.curated_packet,
                      args.private_handoff, args.returned_csv, args.output_dir)
    except (Hold, OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, RecursionError, MemoryError):
        print("HOLD: mismatch among original sources, HUMAN priorities or recipient rows",
              file=sys.stderr)
        return 3
    print("PRIVATE full ORIGINAL HUMAN response CSV prepared for " + str(amount) +
          " selected source ordinals; unverified HUMAN claims, no dispatch/consent.")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
