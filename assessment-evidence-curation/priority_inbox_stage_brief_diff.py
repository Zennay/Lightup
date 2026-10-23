#!/usr/bin/env python3
"""Minimum-necessary, full-source-bound HUMAN stage/priority revision delta.

Both complete original inboxes are re-admitted from the same current source,
selection, every priority handoff and all matching returns. Only rows matching
the explicitly selected priority and belonging to the selected stage before
OR after are included. All HUMAN claims remain unverified.
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
from response import accepted_original, admit_returned_reply
from revision import private_frame

PRIORITIES = ("routine", "soon", "urgent")
REPORT = "PRIVATE-HUMAN-stage-priority-delta.html"
COUNTS = "PRIVATE-HUMAN-stage-priority-delta-counts.json"
RECEIPT = "PRIVATE-HUMAN-stage-priority-delta-receipt.json"
FIELDS = (
    ("recipient_reported_stage", "HUMAN reported stage"),
    ("recipient_human_reply", "HUMAN reply"),
    ("recipient_human_next_question", "HUMAN follow-up question"),
)


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: PRIVATE HUMAN stage/priority revision delta refused")


def build(source_path: str, manifest_path: str, worksheet_path: str,
          selection_receipt: str, selection_path: str, curated_dir: str,
          handoff_paths: list[str], before_reply_paths: list[str],
          before_dir: str, after_reply_paths: list[str], after_dir: str,
          stage: str, priority: str) -> tuple[dict[str, bytes], int]:
    require(stage in dict(STAGES) and priority in PRIORITIES and
            1 <= len(handoff_paths) <= 3 and
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
    ordinals = {row["ordinal"] for row in selected}
    require(set(left) == set(right) == ordinals)

    changed = []
    counts = {
        "rows_before_in_selected_stage": 0,
        "rows_after_in_selected_stage": 0,
        "entered_selected_stage": 0,
        "left_selected_stage": 0,
        "changed_rows_in_selected_priority_scope": 0,
        "changed_stage_fields": 0,
        "changed_reply_fields": 0,
        "changed_follow_up_fields": 0,
    }
    for item in selected:
        ordinal = item["ordinal"]
        before, after = left[ordinal], right[ordinal]
        require(before["priority"] == after["priority"] == item["priority"] and
                before["original_question"] == after["original_question"] == item["question"])
        before_stage = before["recipient_reported_stage"] or "no_human_response"
        after_stage = after["recipient_reported_stage"] or "no_human_response"
        if item["priority"] != priority:
            continue
        if before_stage == stage:
            counts["rows_before_in_selected_stage"] += 1
        if after_stage == stage:
            counts["rows_after_in_selected_stage"] += 1
        if before_stage != stage and after_stage == stage:
            counts["entered_selected_stage"] += 1
        if before_stage == stage and after_stage != stage:
            counts["left_selected_stage"] += 1
        if before_stage != stage and after_stage != stage:
            continue
        differences = [key for key, _ in FIELDS if before[key] != after[key]]
        if not differences:
            continue
        changed.append({
            "ordinal": ordinal,
            "priority": priority,
            "question": item["question"],
            "severity": source["findings"][ordinal - 1]["severity"],
            "evidence_reference_count": len(source["findings"][ordinal - 1]["evidence_ids"]),
            "changed_fields": differences,
            "before": {key: before[key] for key, _ in FIELDS},
            "after": {key: after[key] for key, _ in FIELDS},
        })
        counts["changed_rows_in_selected_priority_scope"] += 1
        counts["changed_stage_fields"] += int("recipient_reported_stage" in differences)
        counts["changed_reply_fields"] += int("recipient_human_reply" in differences)
        counts["changed_follow_up_fields"] += int("recipient_human_next_question" in differences)

    cards = []
    for row in changed:
        details = (
            ("Source-reported severity (UNVERIFIED)", row["severity"]),
            ("Evidence reference count only", str(row["evidence_reference_count"])),
            ("Original HUMAN question (PRIVATE)", row["question"]),
        )
        section = "".join(
            "<dt>" + h(label) + "</dt><dd><pre>" + h(value) + "</pre></dd>"
            for label, value in details)
        for key, label in FIELDS:
            if key not in row["changed_fields"]:
                continue
            before_value = row["before"][key] or "(blank / no HUMAN response)"
            after_value = row["after"][key] or "(blank / no HUMAN response)"
            section += (
                "<dt>Prior " + h(label) + "</dt><dd><pre>" + h(before_value) +
                "</pre></dd><dt>Current " + h(label) + "</dt><dd><pre>" +
                h(after_value) + "</pre></dd>")
        cards.append(
            "<article><h2>Original ordinal #" + str(row["ordinal"]) +
            " · HUMAN priority " + h(priority) + "</h2><p>Changed fields: " +
            h(", ".join(label for key, label in FIELDS if key in row["changed_fields"])) +
            "</p><dl>" + section + "</dl><p>Recipient statements are unverified; "
            "this delta is not evidence of remediation or changed target state.</p></article>")

    body = (
        "<header><h1>LightUp · PRIVATE HUMAN selected stage/priority delta</h1>"
        "<p class='notice'>REVIEW ONLY — only one explicitly selected HUMAN "
        "priority and rows in the selected HUMAN stage before or after are shown. "
        "No identity, verified finding, remediation, consent or authorization is inferred.</p>"
        "<p>Stage: <strong>" + h(stage) + "</strong> · priority: <strong>" +
        h(priority) + "</strong>. Both complete PRIVATE inbox revisions were "
        "rebuilt from the same current original source, selection, full curated "
        "packet, every matching priority handoff and every complete HUMAN return. "
        "Neither inbox was changed.</p>"
        "<p>Rows in selected stage before: " + str(counts["rows_before_in_selected_stage"]) +
        " · after: " + str(counts["rows_after_in_selected_stage"]) +
        " · entered stage: " + str(counts["entered_selected_stage"]) +
        " · left stage: " + str(counts["left_selected_stage"]) +
        " · changed rows in this limited view: " +
        str(counts["changed_rows_in_selected_priority_scope"]) + ".</p>"
        "<p>HUMAN questions and replies may reveal client identity. Keep PRIVATE "
        "and obtain separate current disclosure authority before any sharing.</p></header>" +
        ("".join(cards) if cards else
         "<section><h2>No changed HUMAN fields in the selected stage/priority scope</h2>"
         "<p>No changed rows are shown; this does not mean issues are resolved.</p></section>"))
    report = private_frame("PRIVATE HUMAN selected stage/priority revision delta", body)
    count_doc = {
        "schema": "lightup.private_human_stage_priority_delta_counts.v1",
        "status": "REVIEW_ONLY",
        "human_stage": stage,
        "human_priority": priority,
        **counts,
        **UNTRUSTED_FLAGS,
    }
    receipt = {
        "schema": "lightup.private_human_stage_priority_delta_receipt.v1",
        "status": "REVIEW_ONLY",
        "human_stage": stage,
        "human_priority": priority,
        "original_source_sha256_unsigned": source_sha,
        "original_worksheet_sha256_unsigned": worksheet_sha,
        "original_selection_sha256_unsigned": digest(selection_raw),
        "before_inbox_receipt_sha256_unsigned": digest(before_files[RECEIPT_OUT]),
        "after_inbox_receipt_sha256_unsigned": digest(after_files[RECEIPT_OUT]),
        "before_unified_human_csv_sha256_unsigned": digest(before_files[FINAL]),
        "after_unified_human_csv_sha256_unsigned": digest(after_files[FINAL]),
        "private_delta_html_sha256_unsigned": digest(report),
        "private_delta_counts_sha256_unsigned": digest(json_bytes(count_doc)),
        "changed_original_ordinals": [row["ordinal"] for row in changed],
        **UNTRUSTED_FLAGS,
    }
    return {REPORT: report, COUNTS: json_bytes(count_doc),
            RECEIPT: json_bytes(receipt)}, len(changed)


def compare(source_path: str, manifest_path: str, worksheet_path: str,
            selection_receipt: str, selection_path: str, curated_dir: str,
            handoff_paths: list[str], before_reply_paths: list[str],
            before_dir: str, after_reply_paths: list[str], after_dir: str,
            stage: str, priority: str, output_dir: str) -> int:
    ensure_output_outside_inputs(output_dir, [
        curated_dir, *handoff_paths, before_dir, after_dir])
    files, count = build(
        source_path, manifest_path, worksheet_path, selection_receipt,
        selection_path, curated_dir, handoff_paths, before_reply_paths,
        before_dir, after_reply_paths, after_dir, stage, priority)
    publish_new(output_dir, files)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare a single source-bound PRIVATE HUMAN stage/priority scope")
    for key in ("source", "manifest", "worksheet", "selection-receipt", "selection",
                "curated-packet", "before-private-inbox", "after-private-inbox",
                "output-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--before-returned-csv", action="append", required=True)
    parser.add_argument("--after-returned-csv", action="append", required=True)
    parser.add_argument("--human-stage", choices=[key for key, _ in STAGES], required=True)
    parser.add_argument("--human-priority", choices=PRIORITIES, required=True)
    args = parser.parse_args()
    try:
        changed = compare(
            args.source, args.manifest, args.worksheet, args.selection_receipt,
            args.selection, args.curated_packet, args.private_handoff,
            args.before_returned_csv, args.before_private_inbox,
            args.after_returned_csv, args.after_private_inbox,
            args.human_stage, args.human_priority, args.output_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError):
        print("HOLD: full source-bound HUMAN inbox revision admission failed; "
              "no output changed", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN stage/priority delta prepared: " + str(changed) +
          " changed rows; REVIEW_ONLY, no dispatch or authorization.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
