#!/usr/bin/env python3
"""Offline, separately published source-bound PRIVATE HUMAN follow-up docket.

Unlike aggregate portfolio, this explicitly includes original HUMAN questions
and the latest HUMAN reply. Never auto-publish inside the aggregate folder.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import io
import os
import sys

from curate import Hold, digest
from briefing import h, json_bytes, publish_new
from priority_inbox import FINAL, RECEIPT_OUT, ensure_output_outside_inputs
from priority_inbox_open import reopen_expected
from priority_reply import UNTRUSTED_FLAGS
from response import accepted_original, admit_returned_reply
from revision import private_frame
from priority_inbox_continuity_studio import NAME as STUDIO, build as build_studio

HTML = "PRIVATE-HUMAN-continuity-followup.html"
CSV = "PRIVATE-HUMAN-continuity-followup.csv"
COUNTS = "PRIVATE-HUMAN-continuity-counts.json"
RECEIPT = "PRIVATE-HUMAN-continuity-receipt.json"
PRIORITIES = ("urgent", "soon", "routine")
STAGES = ("no_human_response", "blocked_human",
          "needs_more_information", "responded_claimed")
LIMIT = 512 * 1024
FILTERS = ("attention", "reopened", "unanswered", "all")
BUCKETS = (
    ("reopened_after_claim", "Reopened after a claimed HUMAN response"),
    ("no_response_all_rounds", "No HUMAN response in any round"),
    ("blocked_human", "Latest HUMAN report: blocked"),
    ("needs_more_information", "Latest HUMAN report: needs information"),
    ("awaiting_human", "Latest HUMAN report: no response"),
    ("response_claimed_review_only", "Claimed HUMAN response: independent review"),
)


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: original-source PRIVATE HUMAN follow-up data invalid")


def require_outside_aggregate_folder(destination: str) -> None:
    """Prevent confidential original HUMAN text from nesting in a counts-only pack."""
    parent = os.path.dirname(os.path.realpath(os.path.abspath(destination)))
    while True:
        if os.path.lexists(os.path.join(
                parent, "PRIVATE-HUMAN-priority-round-portfolio.json")):
            raise Hold("HOLD: source-bearing HUMAN docket must be outside the "
                       "aggregate-only PRIVATE HUMAN portfolio")
        next_parent = os.path.dirname(parent)
        if next_parent == parent:
            break
        parent = next_parent


def build(source_path: str, manifest_path: str, worksheet_path: str,
          selection_receipt: str, selection_path: str, curated_dir: str,
          handoffs: list[str], round_replies: list[list[str]],
          round_inboxes: list[str], filter_mode: str,
          human_ordinals: list[int] | None = None
          ) -> tuple[dict[str, bytes], int]:
    rounds = len(round_inboxes)
    require(filter_mode in FILTERS and 2 <= rounds <= 8 and
            1 <= len(handoffs) <= 3 and len(set(handoffs)) == len(handoffs) and
            len(round_replies) == rounds and len(set(round_inboxes)) == rounds and
            all(len(replies) == len(handoffs) and
                len(set(replies)) == len(replies) for replies in round_replies))
    source, source_sha, worksheet_sha, selection_raw, selected = accepted_original(
        source_path, manifest_path, worksheet_path, selection_receipt, selection_path)
    require(1 <= len(selected) <= 64)
    require(all(item["priority"] in PRIORITIES for item in selected))
    by_id = {item["ordinal"]: item for item in selected}
    require(len(by_id) == len(selected))
    ordinals = [] if human_ordinals is None else human_ordinals
    require(type(ordinals) is list and len(ordinals) <= 16 and
            all(type(ordinal) is int and ordinal > 0 for ordinal in ordinals)
            and len(set(ordinals)) == len(ordinals) and
            all(ordinal in by_id for ordinal in ordinals))
    ordinal_selection = set(ordinals)
    ordered = []
    inbox_hashes, reply_hashes = [], []
    for returns, inbox in zip(round_replies, round_inboxes):
        files, count = reopen_expected(
            source_path, manifest_path, worksheet_path, selection_receipt,
            selection_path, curated_dir, handoffs, returns, inbox)
        require(count == len(selected))
        admitted = admit_returned_reply(files[FINAL], source, selected)
        round_by_id = {item["ordinal"]: item for item in admitted}
        require(len(round_by_id) == len(selected) and
                set(round_by_id) == set(by_id))
        for ordinal, original in by_id.items():
            item = round_by_id[ordinal]
            require(item["priority"] == original["priority"] and
                    item["original_question"] == original["question"])
        ordered.append(round_by_id)
        inbox_hashes.append(digest(files[RECEIPT_OUT]))
        reply_hashes.append(digest(files[FINAL]))

    cards, data_rows, studio_rows = [], [], []
    stages_count = Counter()
    selected_counts = Counter()
    for original in sorted(selected, key=lambda r: (PRIORITIES.index(r["priority"]),
                                                      r["ordinal"])):
        ordinal = original["ordinal"]
        history = [item[ordinal] for item in ordered]
        stages = [row["recipient_reported_stage"] or "no_human_response"
                  for row in history]
        require(all(stage in STAGES for stage in stages))
        latest = history[-1]
        attention = stages[-1] != "responded_claimed"
        reopened = attention and "responded_claimed" in stages[:-1]
        unanswered = all(stage == "no_human_response" for stage in stages)
        continuous_attention = all(stage != "responded_claimed" for stage in stages)
        qualifies = (filter_mode == "all" or
                     filter_mode == "attention" and attention or
                     filter_mode == "reopened" and reopened or
                     filter_mode == "unanswered" and unanswered)
        if ordinal_selection and ordinal not in ordinal_selection:
            continue
        if ordinal_selection and not qualifies:
            raise Hold("HOLD: explicit original HUMAN ordinal is outside selected filter")
        if not qualifies:
            continue
        stages_count[stages[-1]] += 1
        bucket = (
            "reopened_after_claim" if reopened else
            "no_response_all_rounds" if unanswered else
            "blocked_human" if stages[-1] == "blocked_human" else
            "needs_more_information" if stages[-1] == "needs_more_information" else
            "awaiting_human" if stages[-1] == "no_human_response" else
            "response_claimed_review_only")
        selected_counts["bucket_" + bucket] += 1
        selected_counts["selected"] += 1
        selected_counts["reopened"] += int(reopened)
        selected_counts["unanswered"] += int(unanswered)
        selected_counts["attention"] += int(attention)
        selected_counts["continuously_awaiting"] += int(continuous_attention)
        f = source["findings"][ordinal - 1]
        studio_rows.append({
            "ordinal": ordinal,
            "priority": original["priority"],
            "bucket": bucket,
            "question": original["question"],
            "latest_stage": stages[-1],
            "latest_reply": latest["recipient_human_reply"],
            "next_question": latest["recipient_human_next_question"],
        })
        data_rows.append((
            ordinal, original["priority"], bucket, f["severity"], len(f["evidence_ids"]),
            stages[0], stages[-1], int(attention), int(reopened),
            int(unanswered), int(continuous_attention),
            sum(stages[i] != stages[i-1] for i in range(1, rounds)),
            int(history[-1]["recipient_human_reply"] !=
                history[-2]["recipient_human_reply"]),
            int(history[-1]["recipient_human_next_question"] !=
                history[-2]["recipient_human_next_question"])))
        history_html = "".join(
            "<li><strong>HUMAN round " + str(i+1) + ":</strong> " +
            h(stage) + "</li>"
            for i, stage in enumerate(stages))
        cards.append(
            (original["priority"], bucket, ordinal,
            "<article id='human-ordinal-" + str(ordinal) + "'><h2>Original "
            "HUMAN ordinal #" + str(ordinal) + " · " +
            h(original["priority"]) + "</h2><p><strong>Original reported "
            "severity (unverified):</strong> " + h(f["severity"]) +
            " · <strong>Evidence references (count only):</strong> " +
            str(len(f["evidence_ids"])) + "</p><h3>Original HUMAN question"
            " · PRIVATE</h3><pre>" + h(original["question"]) +
            "</pre><h3>Reported stage in each manually ordered round</h3><ol>" +
            history_html + "</ol><h3>Latest HUMAN reply · PRIVATE"
            " (unverified)</h3><pre>" +
            h(latest["recipient_human_reply"] or "(no reply)") +
            "</pre><h3>Latest HUMAN follow-up question · PRIVATE</h3><pre>" +
            h(latest["recipient_human_next_question"] or "(none)") +
            "</pre><p><strong>HUMAN follow-up:</strong> __________ "
            "<strong>Independent verification:</strong> __________</p>"
            "<p>Nothing dispatched, verified, assigned or closed by this page."
            "</p></article>"))
    header = (
        "original_human_ordinal", "original_human_priority",
        "human_review_bucket_unverified",
        "source_reported_severity_unverified", "source_evidence_reference_count",
        "first_human_stage", "latest_human_stage", "latest_requires_human_attention",
        "reopened_after_claimed_response", "never_received_human_response",
        "attention_in_every_ordered_round", "adjacent_stage_changes",
        "latest_reply_changed_from_previous_round",
        "latest_followup_changed_from_previous_round")
    rank = {name: i for i, (name, _) in enumerate(BUCKETS)}
    cards.sort(key=lambda item: (PRIORITIES.index(item[0]), rank[item[1]], item[2]))
    data_rows.sort(key=lambda item: (PRIORITIES.index(item[1]), rank[item[2]], item[0]))
    studio_by_ordinal = {row["ordinal"]: row for row in studio_rows}
    require(len(studio_by_ordinal) == len(studio_rows) == len(data_rows))
    studio_rows = [studio_by_ordinal[row[0]] for row in data_rows]
    grouped_sections = "".join(
        "<section><h2>" + h(priority) + " · " + h(label) + " (" +
        str(sum(card[0] == priority and card[1] == bucket for card in cards)) +
        ")</h2>" + "".join(card[3] for card in cards
                           if card[0] == priority and card[1] == bucket) +
        "</section>"
        for priority in PRIORITIES
        for bucket, label in BUCKETS
        if any(card[0] == priority and card[1] == bucket for card in cards))
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(header)
    writer.writerows(data_rows)
    table = output.getvalue().encode("utf-8")
    studio = build_studio(studio_rows, digest(table))
    navigation = "".join(
        "<li><a href='#human-ordinal-" + str(row[0]) +
        "'>Original HUMAN ordinal #" + str(row[0]) + " (" +
        h(row[1]) + ", " + h(row[2]) + ")</a></li>"
        for row in data_rows)
    body = (
        "<header><h1>LightUp · PRIVATE original-source HUMAN continuity docket</h1>"
        "<p class='notice'>REVIEW ONLY · HUMAN identity, reported finding, "
        "client/operator consent, authorization, remediation and timestamp "
        "chronology are NOT verified. This is an operator-created local print "
        "dossier, not an assignment, recipient handoff, scan or approval.</p>"
        "<p><strong>Explicit HUMAN source-detail disclosure filter:</strong> " +
        h(filter_mode) + " · " + str(len(data_rows)) + " included original "
        "HUMAN rows, "
        "across " + str(rounds) + " manually ordered complete HUMAN rounds. " +
        ("Explicit original ordinal selection: " +
         ", ".join(str(i) for i in sorted(ordinal_selection)) + "."
         if ordinal_selection else
         "No explicit ordinal restriction: filtered original selection.") +
        "</p>"
        "<p>Contains PRIVATE original questions and latest recipient texts. "
        "These can identify clients. NEVER publish this alongside the "
        "aggregate-only portfolio or share without separate current "
        "HUMAN disclosure authorization. Only original ordinals, reported "
        "severity and evidence-reference counts are copied from lab findings; "
        "no target URLs, evidence bodies or original finding IDs.</p>"
        "<p>Filter semantics: attention means latest stage is not "
        "responded_claimed; reopened means a prior responded_claimed stage "
        "was followed by latest attention; unanswered means all rounds "
        "reported no HUMAN response; all includes every originally selected "
        "HUMAN row. A claimed response never proves resolution.</p></header>"
        "<section><h2>PRIVATE HUMAN editor (locally saved CSV only)</h2>"
        "<p><a href='" + STUDIO + "'>Open standalone PRIVATE HUMAN review "
        "editor</a> to record non-authorizing human notes and save a local "
        "CSV. The original dossier and all source replies stay immutable. "
        "This is an unsigned, unapproved HUMAN draft.</p></section>"
        "<section><h2>Private local review navigation · grouped by original "
        "priority and HUMAN-reported attention category</h2><ol>" +
        navigation + "</ol></section>" +
        (grouped_sections if cards else
         "<section><h2>No original HUMAN rows matched the chosen filter</h2>"
         "<p>Nothing is verified or resolved as a result.</p></section>"))
    report = private_frame("PRIVATE HUMAN original-source follow-up", body)
    counts = {
        "schema": "lightup.private_human_continuity_docket.v4",
        "status": "REVIEW_ONLY", "operator_filter": filter_mode,
        "explicit_operator_ordinal_filter_applied": bool(ordinal_selection),
        "docket_rows": len(data_rows),
        "ordered_complete_rounds": rounds,
        "reported_latest_stage_counts_included_rows": dict(sorted(stages_count.items())),
        "docket_unverified_summary": dict(sorted(selected_counts.items())),
        "round_order_authenticated": False,
        **UNTRUSTED_FLAGS,
    }
    counts_raw = json_bytes(counts)
    receipt = {
        "schema": "lightup.private_human_continuity_docket_receipt.v4",
        "status": "REVIEW_ONLY", "operator_filter": filter_mode,
        "original_source_sha256_unsigned": source_sha,
        "original_human_worksheet_sha256_unsigned": worksheet_sha,
        "original_human_selection_sha256_unsigned": digest(selection_raw),
        "all_round_original_inbox_receipt_sha256_unsigned": inbox_hashes,
        "all_round_complete_human_csv_sha256_unsigned": reply_hashes,
        "private_html_sha256_unsigned": digest(report),
        "private_csv_sha256_unsigned": digest(table),
        "private_studio_html_sha256_unsigned": digest(studio),
        "private_counts_sha256_unsigned": digest(counts_raw),
        "explicit_operator_original_ordinals": sorted(ordinal_selection),
        "selected_original_ordinals": [r[0] for r in data_rows],
        **UNTRUSTED_FLAGS,
    }
    files = {HTML: report, CSV: table, STUDIO: studio, COUNTS: counts_raw,
             RECEIPT: json_bytes(receipt)}
    require(all(0 < len(raw) <= LIMIT for raw in files.values()))
    return files, len(data_rows)


def publish(*args) -> int:
    (*sources, dest) = args
    require_outside_aggregate_folder(dest)
    ensure_output_outside_inputs(dest, [sources[5], *sources[6], *sources[8]])
    files, count = build(*sources)
    publish_new(dest, files)
    return count


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a separately saved PRIVATE HUMAN source-bound follow-up docket")
    for key in ("source", "manifest", "worksheet", "selection-receipt",
                "selection", "curated-packet"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--output-dir",
                        help="exclusive NEW PRIVATE folder (required unless --preview-only)")
    parser.add_argument("--preview-only", action="store_true",
                        help="readmit all original sources, count matches; create no file")
    parser.add_argument("--private-handoff", action="append", required=True)
    parser.add_argument("--round-inbox", action="append", required=True)
    parser.add_argument("--round-returned-csv", action="append", required=True)
    parser.add_argument("--filter", choices=FILTERS, default="attention")
    parser.add_argument("--human-ordinal", action="append", type=int,
                        help="limit PRIVATE dossier to this exact original selected ordinal; repeat max 16")
    return parser.parse_args()


def main() -> int:
    a = arguments()
    try:
        n = len(a.round_inbox)
        groups = len(a.private_handoff)
        require(2 <= n <= 8 and 1 <= groups <= 3 and
                len(a.round_returned_csv) == n * groups)
        returns = [a.round_returned_csv[i:i+groups]
                   for i in range(0, n * groups, groups)]
        args = (a.source, a.manifest, a.worksheet, a.selection_receipt,
                a.selection, a.curated_packet, a.private_handoff, returns,
                a.round_inbox, a.filter, a.human_ordinal or [])
        if a.preview_only:
            count = build(*args)[1]
        else:
            require(bool(a.output_dir))
            count = publish(*args, a.output_dir)
    except (Hold, OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, MemoryError, RecursionError, csv.Error):
        print("HOLD: original-source private follow-up refused; no output changed",
              file=sys.stderr)
        return 3
    if a.preview_only:
        print("READ-ONLY PRIVATE source-bound HUMAN follow-up preview: " +
              str(count) + " original rows match; NO dossier created, "
              "NO recipient verification or authority.")
    else:
        print("PRIVATE source-bound HUMAN follow-up docket created for " +
              str(count) + " original rows; no release, task or authority.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
