#!/usr/bin/env python3
"""Source-bound 2–8-round HUMAN timeline for one selected stage and priority."""
from __future__ import annotations

import argparse
import sys

from briefing import h, json_bytes, publish_new
from curate import Hold, digest
from priority_inbox import FINAL, RECEIPT_OUT, ensure_output_outside_inputs
from priority_inbox_open import reopen_expected
from priority_inbox_action_queue import STAGES
from priority_reply import UNTRUSTED_FLAGS
from response import accepted_original, admit_returned_reply
from revision import private_frame

PRIORITIES = ("routine", "soon", "urgent")
REPORT = "PRIVATE-HUMAN-stage-priority-timeline.html"
COUNTS = "PRIVATE-HUMAN-stage-priority-timeline-counts.json"
RECEIPT = "PRIVATE-HUMAN-stage-priority-timeline-receipt.json"


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: PRIVATE HUMAN timeline source lineage refused")


def build(source_path: str, manifest_path: str, worksheet_path: str,
          selection_receipt: str, selection_path: str, curated_dir: str,
          handoff_paths: list[str], round_reply_paths: list[list[str]],
          round_inboxes: list[str], stage: str,
          priority: str) -> tuple[dict[str, bytes], int]:
    rounds = len(round_inboxes)
    require(stage in dict(STAGES) and priority in PRIORITIES and
            2 <= rounds <= 8 and len(round_reply_paths) == rounds and
            1 <= len(handoff_paths) <= 3 and
            all(len(group) == len(handoff_paths) for group in round_reply_paths))
    reopened = []
    for replies, inbox in zip(round_reply_paths, round_inboxes):
        files, count = reopen_expected(
            source_path, manifest_path, worksheet_path, selection_receipt,
            selection_path, curated_dir, handoff_paths, replies, inbox)
        reopened.append((files, count))
    require(len({count for _, count in reopened}) == 1)
    source, source_sha, worksheet_sha, selection_raw, selected = accepted_original(
        source_path, manifest_path, worksheet_path, selection_receipt, selection_path)
    notes_by_round = []
    receipts, csv_hashes = [], []
    for files, _ in reopened:
        notes = admit_returned_reply(files[FINAL], source, selected)
        notes_by_round.append({row["ordinal"]: row for row in notes})
        receipts.append(digest(files[RECEIPT_OUT]))
        csv_hashes.append(digest(files[FINAL]))
    original_ordinals = {row["ordinal"] for row in selected}
    require(all(set(round_rows) == original_ordinals for round_rows in notes_by_round))

    timeline = []
    selected_priority = [row for row in selected if row["priority"] == priority]
    stage_counts = []
    entered = left = changed = 0
    for round_rows in notes_by_round:
        stage_counts.append(sum(
            round_rows[row["ordinal"]]["recipient_reported_stage"] == stage
            for row in selected_priority))
    for item in selected_priority:
        ordinal = item["ordinal"]
        entries = [rows[ordinal] for rows in notes_by_round]
        stages = [row["recipient_reported_stage"] for row in entries]
        if stage not in stages:
            continue
        for before, after in zip(stages, stages[1:]):
            entered += int(before != stage and after == stage)
            left += int(before == stage and after != stage)
        fields_changed = any(
            entries[i][key] != entries[i - 1][key]
            for i in range(1, rounds)
            for key in ("recipient_reported_stage", "recipient_human_reply",
                        "recipient_human_next_question"))
        changed += int(fields_changed)
        timeline.append((item, entries))

    cards = []
    for item, entries in timeline:
        ordinal = item["ordinal"]
        finding = source["findings"][ordinal - 1]
        parts = (
            "<dt>Original HUMAN question (PRIVATE)</dt><dd><pre>" +
            h(item["question"]) + "</pre></dd>"
            "<dt>Source-reported severity (UNVERIFIED)</dt><dd><pre>" +
            h(finding["severity"]) + "</pre></dd>"
            "<dt>Evidence reference count only</dt><dd>" +
            str(len(finding["evidence_ids"])) + "</dd>")
        for index, row in enumerate(entries, 1):
            current_stage = row["recipient_reported_stage"]
            parts += ("<dt>Operator-ordered round " + str(index) +
                      " · HUMAN-reported stage</dt><dd><pre>" +
                      h(current_stage) + "</pre></dd>")
            if current_stage == stage:
                parts += (
                    "<dt>Round " + str(index) + " · HUMAN reply (UNVERIFIED)</dt><dd><pre>" +
                    h(row["recipient_human_reply"] or "(no reply)") + "</pre></dd>"
                    "<dt>Round " + str(index) + " · HUMAN next question (PRIVATE)</dt><dd><pre>" +
                    h(row["recipient_human_next_question"] or "(none)") + "</pre></dd>")
            else:
                parts += ("<dt>Round " + str(index) +
                          " · HUMAN text</dt><dd>Withheld: outside the selected stage</dd>")
        cards.append(
            "<article><h2>Original ordinal #" + str(ordinal) +
            " · selected priority " + h(priority) + "</h2><dl>" + parts +
            "</dl><p>Human-entered status and text are unverified; no remediation "
            "or authorization is inferred.</p></article>")

    body = (
        "<header><h1>LightUp · PRIVATE HUMAN stage/priority timeline</h1>"
        "<p class='notice'>REVIEW ONLY · the round order is supplied manually by "
        "the operator; it is not authenticated chronology. Human replies are "
        "unverified, and no client identity, finding validity, remediation, "
        "consent or authorization is inferred.</p>"
        "<p>Selected stage: <strong>" + h(stage) + "</strong> · priority: <strong>" +
        h(priority) + "</strong> · operator-ordered inbox revisions: " +
        str(rounds) + ".</p><p>Every complete inbox was independently re-admitted "
        "from the same original source, selection, curated packet, all priority "
        "handoffs and each matching complete HUMAN return. Only rows in the "
        "selected priority that entered the chosen stage at least once are shown. "
        "Reply and follow-up text is displayed only for rounds reporting the "
        "selected stage.</p><p>Per-round rows in selected stage: " +
        " · ".join("round " + str(i + 1) + ": " + str(n)
                   for i, n in enumerate(stage_counts)) +
        " · stage entries across adjacent rounds: " + str(entered) +
        " · stage exits: " + str(left) + " · rows with any HUMAN-field change: " +
        str(changed) + ".</p><p>Questions/replies may reveal clients. PRIVATE only; "
        "separate current disclosure authorization is required before sharing.</p></header>" +
        ("".join(cards) if cards else
         "<section><h2>No rows entered the selected stage</h2>"
         "<p>No HUMAN notes are shown. This does not mean any issue is resolved.</p></section>"))
    report = private_frame("PRIVATE HUMAN stage/priority multi-round timeline", body)
    counts = {
        "schema": "lightup.private_human_stage_priority_timeline_counts.v1",
        "status": "REVIEW_ONLY",
        "human_stage": stage,
        "human_priority": priority,
        "operator_ordered_round_count": rounds,
        "selected_priority_rows": len(selected_priority),
        "rows_ever_in_selected_stage": len(timeline),
        "rows_with_any_human_field_change": changed,
        "round_selected_stage_counts": stage_counts,
        "adjacent_stage_entries": entered,
        "adjacent_stage_exits": left,
        **UNTRUSTED_FLAGS,
    }
    receipt = {
        "schema": "lightup.private_human_stage_priority_timeline_receipt.v1",
        "status": "REVIEW_ONLY",
        "human_stage": stage,
        "human_priority": priority,
        "operator_ordered_round_count": rounds,
        "original_source_sha256_unsigned": source_sha,
        "original_worksheet_sha256_unsigned": worksheet_sha,
        "original_selection_sha256_unsigned": digest(selection_raw),
        "round_inbox_receipt_sha256_unsigned": receipts,
        "round_unified_human_csv_sha256_unsigned": csv_hashes,
        "private_timeline_html_sha256_unsigned": digest(report),
        "private_timeline_counts_sha256_unsigned": digest(json_bytes(counts)),
        "included_original_ordinals": [item["ordinal"] for item, _ in timeline],
        **UNTRUSTED_FLAGS,
    }
    return {REPORT: report, COUNTS: json_bytes(counts),
            RECEIPT: json_bytes(receipt)}, len(timeline)


def publish(source_path: str, manifest_path: str, worksheet_path: str,
            selection_receipt: str, selection_path: str, curated_dir: str,
            handoff_paths: list[str], round_reply_paths: list[list[str]],
            round_inboxes: list[str], stage: str, priority: str,
            output_dir: str) -> int:
    ensure_output_outside_inputs(output_dir, [
        curated_dir, *handoff_paths, *round_inboxes])
    files, count = build(
        source_path, manifest_path, worksheet_path, selection_receipt,
        selection_path, curated_dir, handoff_paths, round_reply_paths,
        round_inboxes, stage, priority)
    publish_new(output_dir, files)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a source-bound 2–8 round PRIVATE HUMAN stage/priority timeline")
    for key in ("source", "manifest", "worksheet", "selection-receipt",
                "selection", "curated-packet", "output-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--round-inbox", action="append", required=True,
                        help="existing complete PRIVATE inbox; repeat in explicit operator order")
    parser.add_argument("--round-returned-csv", action="append", required=True,
                        help="matching complete HUMAN return CSVs in round-major, priority-group order")
    parser.add_argument("--human-stage", choices=[key for key, _ in STAGES], required=True)
    parser.add_argument("--human-priority", choices=PRIORITIES, required=True)
    args = parser.parse_args()
    try:
        rounds = len(args.round_inbox)
        if not 2 <= rounds <= 8 or len(args.round_returned_csv) != rounds * len(args.private_handoff):
            raise Hold("HOLD: provide 2–8 inboxes and one matching complete return per priority per round")
        group_count = len(args.private_handoff)
        reply_groups = [args.round_returned_csv[i:i + group_count]
                        for i in range(0, len(args.round_returned_csv), group_count)]
        count = publish(
            args.source, args.manifest, args.worksheet, args.selection_receipt,
            args.selection, args.curated_packet, args.private_handoff,
            reply_groups, args.round_inbox, args.human_stage,
            args.human_priority, args.output_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError):
        print("HOLD: complete source-bound HUMAN timeline admission failed; "
              "nothing published", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN stage/priority timeline published for " + str(count) +
          " original ordinals across " + str(len(args.round_inbox)) +
          " operator-ordered inbox revisions; REVIEW_ONLY, no authority.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
