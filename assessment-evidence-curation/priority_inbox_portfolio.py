#!/usr/bin/env python3
"""PRIVATE source-bound HUMAN cross-priority portfolio for 2–8 saved inboxes.

Never tests targets, sends communications, makes authorization decisions, or
interprets human self-reports as remediation. All data remains PRIVATE.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import io
import sys

from curate import Hold, digest
from briefing import h, json_bytes, publish_new
from priority_inbox import FINAL, RECEIPT_OUT, ensure_output_outside_inputs
from priority_inbox_open import reopen_expected
from priority_inbox_action_queue import STAGES
from priority_reply import UNTRUSTED_FLAGS
from response import accepted_original, admit_returned_reply
from revision import private_frame
from priority_inbox_portfolio_browser import build as build_browser
from priority_inbox_portfolio_start import build as build_start

PRIORITIES = ("urgent", "soon", "routine")
STAGE_KEYS = ("no_human_response",) + tuple(key for key, _ in STAGES if key != "no_human_response")
REPORT = "PRIVATE-HUMAN-priority-round-portfolio.html"
COUNTS = "PRIVATE-HUMAN-priority-round-portfolio.json"
CSV = "PRIVATE-HUMAN-priority-round-portfolio.csv"
TRANSITIONS_CSV = "PRIVATE-HUMAN-priority-round-stage-transitions.csv"
INTERVALS_CSV = "PRIVATE-HUMAN-priority-round-intervals.csv"
MOVEMENTS_CSV = "PRIVATE-HUMAN-priority-round-interval-stage-movements.csv"
BROWSER = "PRIVATE-HUMAN-priority-round-explorer.html"
START = "PRIVATE-HUMAN-priority-round-start.html"
RECEIPT = "PRIVATE-HUMAN-priority-round-portfolio-receipt.json"
LIMIT = 512 * 1024


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: PRIVATE HUMAN cross-priority portfolio source or shape invalid")


def build(source_path: str, manifest_path: str, worksheet_path: str,
          selection_receipt: str, selection_path: str, curated_dir: str,
          handoff_paths: list[str], round_reply_paths: list[list[str]],
          round_inboxes: list[str]) -> tuple[dict[str, bytes], int]:
    rounds = len(round_inboxes)
    require(2 <= rounds <= 8 and 1 <= len(handoff_paths) <= 3 and
            len(set(handoff_paths)) == len(handoff_paths) and
            len(set(round_inboxes)) == rounds and
            len(round_reply_paths) == rounds and
            all(len(group) == len(handoff_paths) and
                len(set(group)) == len(group) for group in round_reply_paths))
    source, source_sha, worksheet_sha, selection_raw, selected = accepted_original(
        source_path, manifest_path, worksheet_path, selection_receipt, selection_path)
    require(bool(selected) and len(selected) <= 64)
    selected_by_ordinal = {row["ordinal"]: row for row in selected}
    require(len(selected_by_ordinal) == len(selected) and
            all(row["priority"] in PRIORITIES for row in selected))
    ordered = []
    receipt_shas = []
    csv_shas = []
    for replies, inbox in zip(round_reply_paths, round_inboxes):
        files, count = reopen_expected(
            source_path, manifest_path, worksheet_path, selection_receipt,
            selection_path, curated_dir, handoff_paths, replies, inbox)
        require(count == len(selected))
        rows = admit_returned_reply(files[FINAL], source, selected)
        by_id = {row["ordinal"]: row for row in rows}
        require(len(by_id) == len(rows) == len(selected) and
                set(by_id) == set(selected_by_ordinal))
        for ordinal, item in selected_by_ordinal.items():
            row = by_id[ordinal]
            require(row["priority"] == item["priority"] and
                    row["original_question"] == item["question"] and
                    (row["recipient_reported_stage"] or "no_human_response") in STAGE_KEYS)
        ordered.append(by_id)
        receipt_shas.append(digest(files[RECEIPT_OUT]))
        csv_shas.append(digest(files[FINAL]))

    counts = []
    transitions = []
    for index, current in enumerate(ordered):
        for priority in PRIORITIES:
            ids = [ordinal for ordinal, item in selected_by_ordinal.items()
                   if item["priority"] == priority]
            for stage in STAGE_KEYS:
                count = sum((current[ordinal]["recipient_reported_stage"] or
                             "no_human_response") == stage for ordinal in ids)
                counts.append({"operator_ordered_round": index + 1,
                               "human_priority": priority,
                               "human_stage": stage, "human_rows": count})
        if index:
            prior = ordered[index - 1]
            for priority in PRIORITIES:
                ids = [ordinal for ordinal, item in selected_by_ordinal.items()
                       if item["priority"] == priority]
                changed_stage = changed_reply = changed_followup = 0
                stage_pairs = Counter()
                for ordinal in ids:
                    before = prior[ordinal]
                    after = current[ordinal]
                    old_stage = before["recipient_reported_stage"] or "no_human_response"
                    new_stage = after["recipient_reported_stage"] or "no_human_response"
                    if old_stage != new_stage:
                        changed_stage += 1
                        stage_pairs[(old_stage, new_stage)] += 1
                    changed_reply += int(before["recipient_human_reply"] !=
                                         after["recipient_human_reply"])
                    changed_followup += int(before["recipient_human_next_question"] !=
                                            after["recipient_human_next_question"])
                transitions.append({
                    "operator_ordered_from_round": index,
                    "operator_ordered_to_round": index + 1,
                    "human_priority": priority,
                    "stage_changed_rows": changed_stage,
                    "reply_changed_rows": changed_reply,
                    "next_question_changed_rows": changed_followup,
                    "human_stage_transitions": [
                        {"from_stage": old, "to_stage": new, "human_rows": n}
                        for (old, new), n in sorted(stage_pairs.items())],
                })

    interval_rows = []
    for first in range(rounds - 1):
        for last in range(first + 1, rounds):
            for priority in PRIORITIES:
                ids = [ordinal for ordinal, item in selected_by_ordinal.items()
                       if item["priority"] == priority]
                before = ordered[first]
                after = ordered[last]
                changed_stage = changed_reply = changed_followup = reverted = 0
                stage_movements = Counter()
                human_attention_before = human_attention_after = 0
                human_attention_entered = human_attention_exited = 0
                human_attention_persisted = 0
                human_attention_continuous = 0
                human_unanswered_continuous = 0
                for ordinal in ids:
                    old = before[ordinal]
                    new = after[ordinal]
                    left_stage = old["recipient_reported_stage"] or "no_human_response"
                    right_stage = new["recipient_reported_stage"] or "no_human_response"
                    is_attention_before = left_stage != "responded_claimed"
                    is_attention_after = right_stage != "responded_claimed"
                    human_attention_before += int(is_attention_before)
                    human_attention_after += int(is_attention_after)
                    human_attention_entered += int(
                        not is_attention_before and is_attention_after)
                    human_attention_exited += int(
                        is_attention_before and not is_attention_after)
                    human_attention_persisted += int(
                        is_attention_before and is_attention_after)
                    interval_stages = [
                        ordered[step][ordinal]["recipient_reported_stage"] or
                        "no_human_response"
                        for step in range(first, last + 1)]
                    human_attention_continuous += int(
                        all(stage != "responded_claimed"
                            for stage in interval_stages))
                    human_unanswered_continuous += int(
                        all(stage == "no_human_response"
                            for stage in interval_stages))
                    stage_movements[(left_stage, right_stage)] += 1
                    changed_stage += int(left_stage != right_stage)
                    changed_reply += int(old["recipient_human_reply"] !=
                                         new["recipient_human_reply"])
                    changed_followup += int(old["recipient_human_next_question"] !=
                                            new["recipient_human_next_question"])
                    if left_stage == right_stage and any(
                        (ordered[middle][ordinal]["recipient_reported_stage"] or
                         "no_human_response") != left_stage
                        for middle in range(first + 1, last)
                    ):
                        reverted += 1
                interval_rows.append({
                    "operator_ordered_from_round": first + 1,
                    "operator_ordered_to_round": last + 1,
                    "human_priority": priority,
                    "human_rows_in_priority": len(ids),
                    "human_attention_before_rows": human_attention_before,
                    "human_attention_after_rows": human_attention_after,
                    "human_attention_entered_rows": human_attention_entered,
                    "human_attention_exited_rows": human_attention_exited,
                    "human_attention_persisted_rows": human_attention_persisted,
                    "human_attention_continuous_rows": human_attention_continuous,
                    "human_unanswered_continuous_rows": human_unanswered_continuous,
                    "stage_changed_rows": changed_stage,
                    "intermediate_stage_reverted_rows": reverted,
                    "reply_changed_rows": changed_reply,
                    "next_question_changed_rows": changed_followup,
                    "human_stage_movements": [
                        {"from_stage": old, "to_stage": new, "human_rows": n}
                        for (old, new), n in sorted(stage_movements.items())],
                })

    attention = [
        {"human_priority": priority, "human_stage": stage,
         "human_rows": next(item["human_rows"] for item in counts
                            if item["operator_ordered_round"] == rounds and
                            item["human_priority"] == priority and
                            item["human_stage"] == stage)}
        for priority in PRIORITIES
        for stage in ("blocked_human", "needs_more_information", "no_human_response")
    ]
    numeric = {
        "schema": "lightup.private_human_cross_priority_portfolio.v6",
        "status": "REVIEW_ONLY",
        "operator_ordered_round_count": rounds,
        "selected_original_human_rows": len(selected),
        "round_priority_stage_counts": counts,
        "adjacent_human_round_changes": transitions,
        "latest_round_attention_counts": attention,
        "all_operator_selected_round_intervals": interval_rows,
        "manual_order_not_authenticated_chronology": True,
        **UNTRUSTED_FLAGS,
    }
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(["operator_ordered_round", "human_priority", "human_stage",
                     "human_rows"])
    for item in counts:
        writer.writerow([item["operator_ordered_round"], item["human_priority"],
                         item["human_stage"], item["human_rows"]])
    csv_raw = output.getvalue().encode("utf-8")
    flows_out = io.StringIO(newline="")
    flows_writer = csv.writer(flows_out, lineterminator="\r\n")
    flows_writer.writerow(["operator_ordered_from_round", "operator_ordered_to_round",
                           "human_priority", "from_human_stage", "to_human_stage",
                           "human_rows"])
    for item in transitions:
        for flow in item["human_stage_transitions"]:
            flows_writer.writerow([item["operator_ordered_from_round"],
                                   item["operator_ordered_to_round"],
                                   item["human_priority"], flow["from_stage"],
                                   flow["to_stage"], flow["human_rows"]])
    flows_csv_raw = flows_out.getvalue().encode("utf-8")
    intervals_out = io.StringIO(newline="")
    intervals_writer = csv.writer(intervals_out, lineterminator="\r\n")
    interval_header = (
        "operator_ordered_from_round", "operator_ordered_to_round",
        "human_priority", "human_rows_in_priority",
        "human_attention_before_rows", "human_attention_after_rows",
        "human_attention_entered_rows", "human_attention_exited_rows",
        "human_attention_persisted_rows",
        "human_attention_continuous_rows",
        "human_unanswered_continuous_rows", "stage_changed_rows",
        "intermediate_stage_reverted_rows", "reply_changed_rows",
        "next_question_changed_rows")
    intervals_writer.writerow(interval_header)
    for item in interval_rows:
        intervals_writer.writerow([item[key] for key in interval_header])
    intervals_raw = intervals_out.getvalue().encode("utf-8")
    movement_out = io.StringIO(newline="")
    movement_writer = csv.writer(movement_out, lineterminator="\r\n")
    movement_writer.writerow((
        "operator_ordered_from_round", "operator_ordered_to_round",
        "human_priority", "from_human_stage", "to_human_stage", "human_rows"))
    for interval in interval_rows:
        for change in interval["human_stage_movements"]:
            movement_writer.writerow((
                interval["operator_ordered_from_round"],
                interval["operator_ordered_to_round"],
                interval["human_priority"], change["from_stage"],
                change["to_stage"], change["human_rows"]))
    movements_raw = movement_out.getvalue().encode("utf-8")
    interactive_html = build_browser(interval_rows, rounds, counts, attention)
    start_html = build_start(rounds, len(selected), attention)
    matrix_rows = "".join(
        "<tr><td>" + str(row["operator_ordered_round"]) + "</td><td>" +
        h(row["human_priority"]) + "</td><td>" + h(row["human_stage"]) +
        "</td><td>" + str(row["human_rows"]) + "</td></tr>"
        for row in counts)
    trend_rows = "".join(
        "<tr><td>" + str(item["operator_ordered_from_round"]) + " → " +
        str(item["operator_ordered_to_round"]) + "</td><td>" +
        h(item["human_priority"]) + "</td><td>" +
        str(item["stage_changed_rows"]) + "</td><td>" +
        str(item["reply_changed_rows"]) + "</td><td>" +
        str(item["next_question_changed_rows"]) + "</td></tr>"
        for item in transitions)
    attention_rows = "".join(
        "<tr><td>" + h(item["human_priority"]) + "</td><td>" +
        h(item["human_stage"]) + "</td><td>" +
        str(item["human_rows"]) + "</td></tr>"
        for item in attention)
    flow_rows = "".join(
        "<tr><td>" + str(item["operator_ordered_from_round"]) + " → " +
        str(item["operator_ordered_to_round"]) + "</td><td>" +
        h(item["human_priority"]) + "</td><td>" +
        h(flow["from_stage"]) + "</td><td>" + h(flow["to_stage"]) +
        "</td><td>" + str(flow["human_rows"]) + "</td></tr>"
        for item in transitions for flow in item["human_stage_transitions"])
    body = (
        "<header><h1>LightUp · PRIVATE HUMAN cross-priority portfolio</h1>"
        "<p class='notice'>REVIEW ONLY · offline comparison of manually ordered "
        "HUMAN self-reports. Order is not authenticated chronology; changes "
        "do not imply verified progress, repair, permission, consent or release.</p>"
        "<p>All original source, selected findings, separate priority handoffs, "
        "complete HUMAN returns and exact saved inbox bytes were re-admitted. "
        "Only numeric counts and fixed status/priority names are copied. "
        "No original targets, source IDs, ordinals, HUMAN questions or replies.</p>"
        "<p>Small counts can still be identifying; keep all outputs PRIVATE. "
        "No network, message, task assignment or active assessment was run.</p>"
        "<p>Selected original HUMAN rows: " + str(len(selected)) +
        " · operator-ordered rounds: " + str(rounds) + ".</p></header>"
        "<section><h2>Status counts by priority and round</h2><table>"
        "<thead><tr><th>Round</th><th>HUMAN priority</th><th>HUMAN stage</th>"
        "<th>Rows</th></tr></thead><tbody>" + matrix_rows +
        "</tbody></table></section>"
        "<section><h2>Adjacent HUMAN changes (not verified improvement)</h2>"
        "<table><thead><tr><th>Manually ordered rounds</th><th>Priority</th>"
        "<th>Stage changed</th><th>Reply edited</th><th>Next question edited</th>"
        "</tr></thead><tbody>" + trend_rows +
        "</tbody></table></section>"
        "<section><h2>Latest HUMAN attention (unverified, not assigned)</h2>"
        "<p>No response, blocked, and needs-more-information are HUMAN self-"
        "reports, not verified priorities or assigned work.</p><table>"
        "<thead><tr><th>Priority</th><th>HUMAN stage</th><th>Rows</th></tr>"
        "</thead><tbody>" + attention_rows + "</tbody></table></section>"
        "<section><h2>Changed reported stages between adjacent rounds</h2>"
        "<p>Only stage changes are shown; no human questions/replies copied.</p>"
        "<table><thead><tr><th>Rounds</th><th>Priority</th><th>From</th>"
        "<th>To</th><th>Rows</th></tr></thead><tbody>" + flow_rows +
        "</tbody></table></section>"
    )
    html = private_frame("PRIVATE HUMAN cross-priority round portfolio", body)
    counts_raw = json_bytes(numeric)
    receipt = {
        "schema": "lightup.private_human_cross_priority_portfolio_receipt.v6",
        "status": "REVIEW_ONLY",
        "operator_ordered_round_count": rounds,
        "original_source_sha256_unsigned": source_sha,
        "original_worksheet_sha256_unsigned": worksheet_sha,
        "original_selection_sha256_unsigned": digest(selection_raw),
        "round_original_inbox_receipt_sha256_unsigned": receipt_shas,
        "round_original_human_csv_sha256_unsigned": csv_shas,
        "private_html_sha256_unsigned": digest(html),
        "private_counts_sha256_unsigned": digest(counts_raw),
        "private_csv_sha256_unsigned": digest(csv_raw),
        "private_transition_csv_sha256_unsigned": digest(flows_csv_raw),
        "private_intervals_csv_sha256_unsigned": digest(intervals_raw),
        "private_movements_csv_sha256_unsigned": digest(movements_raw),
        "private_explorer_html_sha256_unsigned": digest(interactive_html),
        "private_start_html_sha256_unsigned": digest(start_html),
        **UNTRUSTED_FLAGS,
    }
    files = {REPORT: html, COUNTS: counts_raw, CSV: csv_raw,
             TRANSITIONS_CSV: flows_csv_raw, INTERVALS_CSV: intervals_raw,
             MOVEMENTS_CSV: movements_raw,
             BROWSER: interactive_html, START: start_html,
             RECEIPT: json_bytes(receipt)}
    require(all(0 < len(raw) <= LIMIT for raw in files.values()))
    return files, len(selected)


def publish(source: str, manifest: str, worksheet: str, selection_receipt: str,
            selection: str, curated: str, handoffs: list[str],
            round_replies: list[list[str]], round_inboxes: list[str],
            output_dir: str) -> int:
    ensure_output_outside_inputs(output_dir, [curated, *handoffs, *round_inboxes])
    files, count = build(source, manifest, worksheet, selection_receipt,
                         selection, curated, handoffs, round_replies, round_inboxes)
    publish_new(output_dir, files)
    return count


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a source-reopened offline PRIVATE HUMAN priority/stage round portfolio")
    for key in ("source", "manifest", "worksheet", "selection-receipt",
                "selection", "curated-packet", "output-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--round-inbox", action="append", required=True)
    parser.add_argument("--round-returned-csv", action="append", required=True)
    return parser.parse_args()


def main() -> int:
    args = arguments()
    try:
        rounds = len(args.round_inbox)
        group_count = len(args.private_handoff)
        require(2 <= rounds <= 8 and 1 <= group_count <= 3 and
                len(args.round_returned_csv) == rounds * group_count)
        groups = [args.round_returned_csv[i:i + group_count]
                  for i in range(0, len(args.round_returned_csv), group_count)]
        count = publish(args.source, args.manifest, args.worksheet,
                        args.selection_receipt, args.selection,
                        args.curated_packet, args.private_handoff,
                        groups, args.round_inbox, args.output_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError, csv.Error):
        print("HOLD: original source, HUMAN rounds or PRIVATE output refused; "
              "no partial publication", file=sys.stderr)
        return 3
    print("PRIVATE cross-priority HUMAN portfolio: " + str(count) +
          " source-bound rows; REVIEW_ONLY, no authority.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
