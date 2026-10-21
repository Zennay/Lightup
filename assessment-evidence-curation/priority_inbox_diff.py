#!/usr/bin/env python3
"""Compare two independently source-reopened PRIVATE HUMAN inbox revisions."""
from __future__ import annotations

import argparse
import sys

from curate import Hold, digest
from briefing import h, json_bytes, publish_new
from packet_handoff import RECEIPT as HANDOFF_RECEIPT
from packet_open import json_private
from priority_inbox import FINAL, RECEIPT_OUT, ensure_output_outside_inputs
from priority_inbox_open import reopen_expected
from priority_reconcile import read_owner_dir
from priority_reply import UNTRUSTED_FLAGS
from response import accepted_original, admit_returned_reply
from revision import private_frame

REPORT = "PRIVATE-original-HUMAN-response-delta.html"
COUNTS = "PRIVATE-original-HUMAN-response-delta-counts.json"
RECEIPT_OUT_DELTA = "PRIVATE-original-HUMAN-response-delta-receipt.json"
FIELDS = (
    ("recipient_reported_stage", "HUMAN stage"),
    ("recipient_human_reply", "HUMAN reply"),
    ("recipient_human_next_question", "HUMAN follow-up question"),
)


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: PRIVATE HUMAN response revision comparison refused")


def build(source_path: str, manifest_path: str, worksheet_path: str,
          selection_receipt: str, selection_path: str, curated_dir: str,
          handoff_paths: list[str], before_reply_paths: list[str],
          before_dir: str, after_reply_paths: list[str],
          after_dir: str) -> tuple[dict[str, bytes], int]:
    require(1 <= len(handoff_paths) <= 3 and
            len(handoff_paths) == len(before_reply_paths) ==
            len(after_reply_paths))
    before_files, before_count = reopen_expected(
        source_path, manifest_path, worksheet_path, selection_receipt,
        selection_path, curated_dir, handoff_paths, before_reply_paths, before_dir)
    after_files, after_count = reopen_expected(
        source_path, manifest_path, worksheet_path, selection_receipt,
        selection_path, curated_dir, handoff_paths, after_reply_paths, after_dir)
    require(before_count == after_count)

    source, source_sha, worksheet_sha, selection_raw, selected = accepted_original(
        source_path, manifest_path, worksheet_path, selection_receipt, selection_path)
    before_notes = admit_returned_reply(before_files[FINAL], source, selected)
    after_notes = admit_returned_reply(after_files[FINAL], source, selected)
    left = {row["ordinal"]: row for row in before_notes}
    right = {row["ordinal"]: row for row in after_notes}
    require(set(left) == set(right) == {row["ordinal"] for row in selected})

    changed = []
    per_priority = {
        priority: {"selected_rows": 0, "changed_rows": 0,
                   "stage_changes": 0, "reply_changes": 0,
                   "follow_up_changes": 0}
        for priority in ("routine", "soon", "urgent")
    }
    for item in selected:
        ordinal = item["ordinal"]
        before, after = left[ordinal], right[ordinal]
        require(before["priority"] == after["priority"] == item["priority"] and
                before["original_question"] == after["original_question"] == item["question"])
        priority = item["priority"]
        per_priority[priority]["selected_rows"] += 1
        differences = [key for key, _ in FIELDS if before[key] != after[key]]
        if not differences:
            continue
        row = {
            "ordinal": ordinal, "priority": priority,
            "question": item["question"],
            "severity": source["findings"][ordinal - 1]["severity"],
            "evidence_reference_count": len(source["findings"][ordinal - 1]["evidence_ids"]),
            "changed_fields": differences,
            "before": {key: before[key] for key, _ in FIELDS},
            "after": {key: after[key] for key, _ in FIELDS},
        }
        changed.append(row)
        counts = per_priority[priority]
        counts["changed_rows"] += 1
        counts["stage_changes"] += int("recipient_reported_stage" in differences)
        counts["reply_changes"] += int("recipient_human_reply" in differences)
        counts["follow_up_changes"] += int("recipient_human_next_question" in differences)

    cards = []
    for row in changed:
        values = (
            ("Source-reported severity (UNVERIFIED)", row["severity"]),
            ("Original evidence reference count", str(row["evidence_reference_count"])),
            ("Original HUMAN question", row["question"]),
        )
        section = "".join("<dt>" + h(label) + "</dt><dd><pre>" + h(value) +
                          "</pre></dd>" for label, value in values)
        for key, label in FIELDS:
            if key not in row["changed_fields"]:
                continue
            section += ("<dt>Prior " + h(label) + "</dt><dd><pre>" +
                        h(row["before"][key]) + "</pre></dd><dt>Current " +
                        h(label) + "</dt><dd><pre>" + h(row["after"][key]) +
                        "</pre></dd>")
        cards.append(
            "<article><h2>Original ordinal #" + str(row["ordinal"]) +
            " · HUMAN priority " + h(row["priority"]) + "</h2><p>Changed fields: " +
            h(", ".join(label for key, label in FIELDS if key in row["changed_fields"])) +
            "</p><dl>" + section + "</dl><p>All recipient statements are unverified; "
            "this difference is not evidence of remediation or changed target state.</p></article>"
        )
    body = (
        "<header><h1>LightUp · PRIVATE HUMAN response revision comparison</h1>"
        "<p class='notice'>REVIEW ONLY — source-bound before/after recipient claims. "
        "No recipient identity, finding validity, remediation, consent or authorization "
        "is inferred. No network, target, or outbound action occurred.</p>"
        "<p>Both complete inbox revisions were independently rebuilt from the current "
        "original lab source, worksheet, selection, entire curated packet, each unique "
        "priority handoff and each matching returned HUMAN CSV. The existing inbox "
        "directories were compared read-only; neither was changed.</p>"
        "<p>Original selected HUMAN rows: " + str(len(selected)) +
        " · rows with changed recipient fields: " + str(len(changed)) +
        " · unchanged rows: " + str(len(selected) - len(changed)) +
        ".</p><p>HUMAN question and response text may disclose clients; this report "
        "is PRIVATE and needs separate current disclosure authorization.</p></header>" +
        ("".join(cards) if cards else
         "<section class='card'><h2>No HUMAN response field changes</h2>"
         "<p>The two source-bound CSV revisions contain identical stage, reply and "
         "follow-up values for all selected ordinals.</p></section>")
    )
    report = private_frame("PRIVATE HUMAN response revision comparison", body)
    counts = {
        "schema": "lightup.private_original_human_response_delta_counts.v1",
        "status": "REVIEW_ONLY",
        "original_source_reported_findings": len(source["findings"]),
        "selected_human_count": len(selected),
        "changed_human_row_count": len(changed),
        "unchanged_human_row_count": len(selected) - len(changed),
        "changed_field_counts": {
            label: sum(key in row["changed_fields"] for row in changed)
            for key, label in FIELDS
        },
        "human_priority_counts": per_priority,
        **UNTRUSTED_FLAGS,
    }
    original_packet_raw = read_owner_dir(
        curated_dir, ("PRIVATE-curation-receipt.json",))["PRIVATE-curation-receipt.json"]
    before_receipt_raw = before_files[RECEIPT_OUT]
    after_receipt_raw = after_files[RECEIPT_OUT]
    before_receipt = json_private(before_receipt_raw)
    after_receipt = json_private(after_receipt_raw)
    require(before_receipt["original_source_sha256_unsigned"] ==
            after_receipt["original_source_sha256_unsigned"] == source_sha and
            before_receipt["original_worksheet_sha256_unsigned"] ==
            after_receipt["original_worksheet_sha256_unsigned"] == worksheet_sha and
            before_receipt["original_selection_sha256_unsigned"] ==
            after_receipt["original_selection_sha256_unsigned"] == digest(selection_raw) and
            before_receipt["original_curated_packet_receipt_sha256_unsigned"] ==
            after_receipt["original_curated_packet_receipt_sha256_unsigned"] ==
            digest(original_packet_raw) and
            set(before_receipt["per_human_priority_unsigned_receipts"]) ==
            set(after_receipt["per_human_priority_unsigned_receipts"]))
    handoff_hashes = {}
    for path in handoff_paths:
        raw = read_owner_dir(path, (HANDOFF_RECEIPT,))[HANDOFF_RECEIPT]
        handoff = json_private(raw)
        priority = handoff["source_human_priority"]
        require(priority not in handoff_hashes)
        handoff_hashes[priority] = digest(raw)
    require(set(handoff_hashes) ==
            set(before_receipt["per_human_priority_unsigned_receipts"]) ==
            set(after_receipt["per_human_priority_unsigned_receipts"]))
    for priority, wanted in handoff_hashes.items():
        require(before_receipt["per_human_priority_unsigned_receipts"][priority]
                ["original_handoff_receipt_sha256_unsigned"] == wanted and
                after_receipt["per_human_priority_unsigned_receipts"][priority]
                ["original_handoff_receipt_sha256_unsigned"] == wanted)
    receipt = {
        "schema": "lightup.private_original_human_response_delta.v1",
        "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": source_sha,
        "original_worksheet_sha256_unsigned": worksheet_sha,
        "original_selection_sha256_unsigned": digest(selection_raw),
        "original_curated_packet_receipt_sha256_unsigned": digest(original_packet_raw),
        "priority_handoff_receipt_sha256_unsigned": handoff_hashes,
        "before_inbox_receipt_sha256_unsigned": digest(before_receipt_raw),
        "after_inbox_receipt_sha256_unsigned": digest(after_receipt_raw),
        "before_unified_response_sha256_unsigned": digest(before_files[FINAL]),
        "after_unified_response_sha256_unsigned": digest(after_files[FINAL]),
        "private_delta_report_sha256_unsigned": digest(report),
        "private_delta_counts_sha256_unsigned": digest(json_bytes(counts)),
        "changed_original_ordinals": [row["ordinal"] for row in changed],
        **UNTRUSTED_FLAGS,
    }
    return ({
        REPORT: report, COUNTS: json_bytes(counts),
        RECEIPT_OUT_DELTA: json_bytes(receipt),
    }, len(changed))


def compare(source_path: str, manifest_path: str, worksheet_path: str,
            selection_receipt: str, selection_path: str, curated_dir: str,
            handoff_paths: list[str], before_reply_paths: list[str],
            before_dir: str, after_reply_paths: list[str], after_dir: str,
            output_dir: str) -> int:
    ensure_output_outside_inputs(
        output_dir, [curated_dir, *handoff_paths, before_dir, after_dir])
    files, count = build(source_path, manifest_path, worksheet_path,
                         selection_receipt, selection_path, curated_dir,
                         handoff_paths, before_reply_paths, before_dir,
                         after_reply_paths, after_dir)
    publish_new(output_dir, files)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare two full-lineage PRIVATE HUMAN inbox revisions; no authorization")
    for key in ("source", "manifest", "worksheet", "selection-receipt",
                "selection", "curated-packet", "before-private-dir",
                "after-private-dir", "output-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--before-returned-csv", action="append", required=True)
    parser.add_argument("--after-returned-csv", action="append", required=True)
    args = parser.parse_args()
    try:
        count = compare(args.source, args.manifest, args.worksheet,
                        args.selection_receipt, args.selection, args.curated_packet,
                        args.private_handoff, args.before_returned_csv,
                        args.before_private_dir, args.after_returned_csv,
                        args.after_private_dir, args.output_dir)
    except Hold as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError):
        print("HOLD: PRIVATE HUMAN inbox revisions could not be reconciled; no output claimed",
              file=sys.stderr)
        return 3
    print("PRIVATE HUMAN response delta prepared: " + str(count) +
          " changed original rows; REVIEW_ONLY, no authorization or dispatch.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
