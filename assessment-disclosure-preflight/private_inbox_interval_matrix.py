"""Bounded all-pairs PRIVATE HUMAN interval matrix; coordination only.

This reuses the original native board/worksheet admission and publication
boundary. It never authenticates chronology, authorizes assessment or proves
remediation, consent, reviewer identity or release.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import os
import sys

import private_inbox_actions as actions
import private_inbox_history as timeline
import private_inbox_interval as interval
from human_review import Hold, source_bytes

OUTPUT_HTML = "PRIVATE-HUMAN-original-interval-matrix.html"
OUTPUT_CSV = "PRIVATE-HUMAN-original-interval-matrix.csv"
OUTPUT_JSON = "PRIVATE-HUMAN-original-interval-matrix.json"
OUTPUT_ATTENTION_CSV = "PRIVATE-HUMAN-original-interval-attention.csv"
FALSE_FLAGS = interval.FALSE_FLAGS


def _count(rows: list[dict], key: str) -> int:
    return sum(row[key] is True for row in rows)


def _compose_attention(history: dict) -> list[dict]:
    """Source-free operator discussion prompts, never automated decisions."""
    events = history["changed_transitions"]
    output = []
    for path in history["slot_paths"]:
        slot = path["slot"]
        related = [e for e in events if e["slot"] == slot]
        stage_count = sum("human_status" in e["changed_fields"] for e in related)
        role_count = sum("proposed_role" in e["changed_fields"] for e in related)
        question_count = sum("question_text_changed" in e["changed_fields"] for e in related)
        action_count = sum("next_action_text_changed" in e["changed_fields"] for e in related)
        beginning, latest = path["rounds"][0], path["rounds"][-1]
        stage_return = stage_count > 0 and beginning["human_status"] == latest["human_status"]
        role_return = role_count > 0 and beginning["proposed_role"] == latest["proposed_role"]
        # Review ordering is illustrative. No severity, verified remedy, owner
        # identity or independent timeline authority can be derived here.
        if stage_return or role_return:
            cue = "HUMAN_REVISIT_REVERTED_EDIT"
        elif stage_count + role_count > 1:
            cue = "HUMAN_REVIEW_MULTIPLE_DECLARED_EDITS"
        elif question_count or action_count:
            cue = "HUMAN_REVIEW_PRIVATE_NOTE_CHURN"
        elif latest["human_status"] in ("UNREVIEWED", "NEEDS_INPUT"):
            cue = "HUMAN_FOLLOW_UP_NOT_COMPLETED"
        else:
            cue = "HUMAN_DISCUSS_NO_RELEASE_INFERRED"
        output.append({
            "slot": slot,
            "manual_round_count": history["round_count"],
            "first_declared_status": beginning["human_status"],
            "latest_declared_status": latest["human_status"],
            "latest_proposed_role": latest["proposed_role"],
            "status_edit_transitions": stage_count,
            "role_edit_transitions": role_count,
            "question_edit_transitions": question_count,
            "next_action_edit_transitions": action_count,
            "stage_returned_to_first_after_edit": stage_return,
            "role_returned_to_first_after_edit": role_return,
            "human_discussion_cue": cue,
            "source_authenticated": False,
            "chronology_authenticated": False,
            "authorization_granted": False,
            "release_allowed": False,
        })
    return output


def compose_matrix(complete_history: dict) -> dict:
    """Build every ordered start/end pair from one admitted complete history."""
    rounds = complete_history["round_count"]
    if type(rounds) is not int or not timeline.MIN_ROUNDS <= rounds <= timeline.MAX_ROUNDS:
        raise ValueError("2–8 complete original HUMAN revisions required")

    pairs = []
    for start in range(1, rounds):
        for end in range(start + 1, rounds + 1):
            report = interval.compose_interval(complete_history, start, end)
            rows = report["all_original_slots"]
            summary = {
                "manual_start_round": start,
                "manual_end_round": end,
                "slots_with_any_declared_human_field_activity":
                    report["slots_with_any_declared_human_field_activity"],
                "status_endpoint_changes": _count(rows, "status_endpoint_changed"),
                "status_edits_during_interval": _count(rows, "status_edited_within_interval"),
                "role_endpoint_changes": _count(rows, "proposed_role_endpoint_changed"),
                "role_edits_during_interval": _count(rows, "role_edited_within_interval"),
                "question_edits_during_interval": _count(rows, "question_edited_within_interval"),
                "next_action_edits_during_interval": _count(rows, "next_action_edited_within_interval"),
            }
            pairs.append({
                **summary,
                "all_original_slots": rows,
            })

    attention = _compose_attention(complete_history)
    attention_totals = {
        "slots_with_declared_stage_reversions": sum(
            row["stage_returned_to_first_after_edit"] for row in attention),
        "slots_with_declared_role_reversions": sum(
            row["role_returned_to_first_after_edit"] for row in attention),
        "slots_with_private_note_edits": sum(
            row["question_edit_transitions"] > 0 or
            row["next_action_edit_transitions"] > 0 for row in attention),
        "slots_with_multiple_stage_or_role_edits": sum(
            row["status_edit_transitions"] + row["role_edit_transitions"] > 1
            for row in attention),
    }
    return {
        "schema": "lightup.private_human_original_interval_matrix.v2",
        "status": "REVIEW_ONLY",
        "source_free": True,
        "original_complete_input_reopening_required": True,
        "manual_order_not_authenticated_chronology": True,
        **{flag: False for flag in FALSE_FLAGS},
        "original_slot_count": complete_history["slot_count"],
        "original_round_count": rounds,
        "pair_count": len(pairs),
        "pair_summaries": [
            {key: value for key, value in pair.items() if key != "all_original_slots"}
            for pair in pairs
        ],
        "all_pairwise_intervals": pairs,
        "human_discussion_attention": attention,
        "attention_counts": attention_totals,
    }


def _display(value) -> str:
    return str(value).lower() if type(value) is bool else str(value)


def render_csv(matrix: dict) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow((
        "manual_start_round", "manual_end_round", *interval.ROW_KEYS,
        "source_authenticated", "chronology_authenticated",
        "authorization_granted", "release_allowed",
    ))
    for pair in matrix["all_pairwise_intervals"]:
        for row in pair["all_original_slots"]:
            writer.writerow([
                pair["manual_start_round"], pair["manual_end_round"],
                *[_display(row[key]) for key in interval.ROW_KEYS],
                "false", "false", "false", "false",
            ])
    return output.getvalue().encode("utf-8")


def render_attention_csv(matrix: dict) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    columns = (
        "slot", "manual_round_count", "first_declared_status",
        "latest_declared_status", "latest_proposed_role",
        "status_edit_transitions", "role_edit_transitions",
        "question_edit_transitions", "next_action_edit_transitions",
        "stage_returned_to_first_after_edit",
        "role_returned_to_first_after_edit", "human_discussion_cue",
        "source_authenticated", "chronology_authenticated",
        "authorization_granted", "release_allowed",
    )
    writer.writerow(columns)
    for row in matrix["human_discussion_attention"]:
        writer.writerow([_display(row[key]) for key in columns])
    return output.getvalue().encode("utf-8")


def render_html(matrix: dict) -> bytes:
    esc = lambda value: html.escape(_display(value), quote=True)
    summary_columns = (
        ("manual_start_round", "From round"),
        ("manual_end_round", "To round"),
        ("slots_with_any_declared_human_field_activity", "Slots with activity"),
        ("status_endpoint_changes", "Stage differs at endpoints"),
        ("status_edits_during_interval", "Stage edited in interval"),
        ("role_endpoint_changes", "Role differs at endpoints"),
        ("role_edits_during_interval", "Role edited in interval"),
        ("question_edits_during_interval", "Question edits"),
        ("next_action_edits_during_interval", "Next-action edits"),
    )
    detail_columns = (
        ("manual_start_round", "From round"),
        ("manual_end_round", "To round"),
        ("slot", "Original slot"),
        ("from_status", "Prior HUMAN stage"),
        ("to_status", "Later HUMAN stage"),
        ("status_endpoint_changed", "Stage differs at endpoints"),
        ("status_edited_within_interval", "Stage edited in interval"),
        ("from_proposed_role", "Prior proposed role"),
        ("to_proposed_role", "Later proposed role"),
        ("proposed_role_endpoint_changed", "Role differs at endpoints"),
        ("role_edited_within_interval", "Role edited in interval"),
        ("question_edited_within_interval", "Question edited"),
        ("next_action_edited_within_interval", "Next action edited"),
        ("original_unselected_holds", "Original HOLD choices"),
    )
    attention_columns = (
        ("slot", "Original slot"),
        ("first_declared_status", "First HUMAN stage"),
        ("latest_declared_status", "Latest HUMAN stage"),
        ("latest_proposed_role", "Latest proposed role"),
        ("status_edit_transitions", "Stage edits"),
        ("role_edit_transitions", "Role edits"),
        ("question_edit_transitions", "Question edits"),
        ("next_action_edit_transitions", "Next-action edits"),
        ("stage_returned_to_first_after_edit", "Stage changed then returned"),
        ("role_returned_to_first_after_edit", "Role changed then returned"),
        ("human_discussion_cue", "HUMAN follow-up cue"),
    )
    attention_rows = [
        "<tr>" + "".join("<td>" + esc(row[key]) + "</td>"
                         for key, label in attention_columns) + "</tr>"
        for row in matrix["human_discussion_attention"]
    ]
    summary_rows = []
    detail_rows = []
    for pair in matrix["all_pairwise_intervals"]:
        summary_rows.append("<tr>" + "".join(
            "<td>" + esc(pair[key]) + "</td>"
            for key, _label in summary_columns
        ) + "</tr>")
        for row in pair["all_original_slots"]:
            detail_rows.append("<tr>" + "".join(
                "<td>" + esc(pair[key] if key in (
                    "manual_start_round", "manual_end_round"
                ) else row[key]) + "</td>"
                for key, _label in detail_columns
            ) + "</tr>")

    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRIVATE HUMAN all-pairs interval matrix</title>
<style>body{font:16px/1.5 system-ui;max-width:1500px;margin:2rem auto;padding:1rem;color:#20314a}
table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}td,th{border:1px solid #abc0d5;padding:.45rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#edf4fb}.warning{border-left:5px solid #8c5900;background:#fff1dd;padding:1rem}
.scroll{overflow-x:auto}@media print{body{margin:0;font-size:10px}.scroll{overflow:visible}tr{break-inside:avoid}}</style></head><body>
<h1>PRIVATE HUMAN all-pairs interval matrix</h1>
<p class="warning"><strong>REVIEW_ONLY / HOLD · INCUBATE M3/M7 PLAN/LAB ONLY.</strong>
All rounds are manually ordered, not authenticated timestamps. Proposed roles are not assignments.
A discussion or changed note is not remediation evidence. This unsigned local report establishes
no source identity, reviewer identity, consent, target clearance, grant or release. Keep private.</p>
<p>Original rounds: <strong>__ROUNDS__</strong>. Original slots: <strong>__SLOTS__</strong>.
All possible earlier/later pairs: <strong>__PAIRS__</strong>. Every pair includes every original slot,
including unchanged slots and intermediate edits that were later reversed.</p>
<h2>Source-free HUMAN follow-up desk</h2>
<p>Declared stage-reversions: <strong>__STAGE_REVERT__</strong>.
Declared role-reversions: <strong>__ROLE_REVERT__</strong>.
Slots with private question/action edits: <strong>__NOTE_EDITS__</strong>.
These are <em>manual-order discussion cues</em>, not priorities assigned by
verified severity, chronology, consent or source identity.</p>
<div class="scroll"><table><thead><tr>__ATTENTION_HEAD__</tr></thead>
<tbody>__ATTENTION_ROWS__</tbody></table></div>
<h2>Pairwise summary</h2><div class="scroll"><table><thead><tr>__SUMMARY_HEAD__</tr></thead><tbody>__SUMMARY_ROWS__</tbody></table></div>
<h2>Complete original-slot detail</h2><div class="scroll"><table><thead><tr>__DETAIL_HEAD__</tr></thead><tbody>__DETAIL_ROWS__</tbody></table></div>
<p>Question and next-action values are never included; their columns mean at least one edit occurred
inside that manually selected interval, not that final text differs. Source files, paths, board hashes,
original notes and reviewer identifiers are omitted. Local byte equality is not external provenance.
Original source-owner, independent security/privacy/browser reviews, #177/#182/#829, separate current
authenticated client/operator consent with action-time revocation and explicit HUMAN GO remain mandatory.
No client contact, scan, dispatch, authorization or release follows from this report.</p>
</body></html>"""
    page = (page.replace("__ROUNDS__", esc(matrix["original_round_count"]))
            .replace("__SLOTS__", esc(matrix["original_slot_count"]))
            .replace("__PAIRS__", esc(matrix["pair_count"]))
            .replace("__STAGE_REVERT__", esc(matrix["attention_counts"]["slots_with_declared_stage_reversions"]))
            .replace("__ROLE_REVERT__", esc(matrix["attention_counts"]["slots_with_declared_role_reversions"]))
            .replace("__NOTE_EDITS__", esc(matrix["attention_counts"]["slots_with_private_note_edits"]))
            .replace("__ATTENTION_HEAD__", "".join(
                "<th scope='col'>" + esc(label) + "</th>"
                for _key, label in attention_columns))
            .replace("__ATTENTION_ROWS__", "".join(attention_rows))
            .replace("__SUMMARY_HEAD__", "".join(
                "<th scope='col'>" + esc(label) + "</th>"
                for _key, label in summary_columns))
            .replace("__SUMMARY_ROWS__", "".join(summary_rows))
            .replace("__DETAIL_HEAD__", "".join(
                "<th scope='col'>" + esc(label) + "</th>"
                for _key, label in detail_columns))
            .replace("__DETAIL_ROWS__", "".join(detail_rows)))
    return page.encode("utf-8")


def expected_artifacts(matrix: dict) -> list[tuple[str, bytes]]:
    return [
        (OUTPUT_HTML, render_html(matrix)),
        (OUTPUT_CSV, render_csv(matrix)),
        (OUTPUT_ATTENTION_CSV, render_attention_csv(matrix)),
        (OUTPUT_JSON, (json.dumps(
            matrix, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ) + "\n").encode("utf-8")),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="All pairwise original PRIVATE HUMAN intervals; no assessment execution"
    )
    parser.add_argument("action", choices=("build", "reopen"))
    parser.add_argument("--board", required=True)
    parser.add_argument("--revision", action="append", required=True)
    parser.add_argument("--private-output-dir")
    parser.add_argument("--preview-only", action="store_true",
                        help="Admit inputs and print aggregate counts without rendering or writing outputs")
    args = parser.parse_args()
    try:
        if args.preview_only and args.action != "build":
            raise ValueError("preview-only is available for build only")
        if args.preview_only and args.private_output_dir is not None:
            raise ValueError("preview-only must not receive an output directory")
        if not args.preview_only and not args.private_output_dir:
            raise ValueError("private output directory required")
        if not timeline.MIN_ROUNDS <= len(args.revision) <= timeline.MAX_ROUNDS:
            raise ValueError("2–8 complete original HUMAN revisions required")
        board_raw = source_bytes(args.board)
        board_digest, originals = actions.board_admit(args.board)
        if hashlib.sha256(board_raw).hexdigest() != board_digest:
            raise ValueError("original board changed during admission")
        revision_raws = [source_bytes(path) for path in args.revision]
        if len(set(revision_raws)) != len(revision_raws):
            raise ValueError("duplicate complete original HUMAN revisions refused")
        revisions = [
            actions.read_human_csv(path, board_digest, originals)
            for path in args.revision
        ]
        matrix = compose_matrix(timeline.compose_history(originals, revisions))
        if not args.preview_only:
            artifacts = expected_artifacts(matrix)
            for source in (args.board, *args.revision):
                actions.board.require_output_outside_source_tree(
                    os.path.dirname(os.path.realpath(source)), args.private_output_dir
                )
        if source_bytes(args.board) != board_raw:
            raise ValueError("original board changed before matrix publication")
        for path, raw in zip(args.revision, revision_raws):
            if source_bytes(path) != raw:
                raise ValueError("original HUMAN worksheet changed before matrix publication")
        if args.preview_only:
            pair_slot_rows = sum(
                len(pair["all_original_slots"])
                for pair in matrix["all_pairwise_intervals"]
            )
            print("PRIVATE_HUMAN_INTERVAL_MATRIX_PREVIEW — REVIEW_ONLY"
                  + "; rounds=" + str(matrix["original_round_count"])
                  + "; slots=" + str(matrix["original_slot_count"])
                  + "; pairs=" + str(matrix["pair_count"])
                  + "; pair_slot_rows=" + str(pair_slot_rows)
                  + "; stage_reversions=" + str(matrix["attention_counts"]["slots_with_declared_stage_reversions"])
                  + "; role_reversions=" + str(matrix["attention_counts"]["slots_with_declared_role_reversions"])
                  + "; no_files_written; no_authority")
            return 2
        if args.action == "build":
            actions.publish_private_artifacts(args.private_output_dir, artifacts)
        else:
            actions.reopen_private_artifacts(args.private_output_dir, artifacts)
        print("REVIEW_ONLY: PRIVATE HUMAN all-pairs interval matrix", args.action,
              "completed; no chronology, consent, assessment or release")
        return 2
    except (OSError, ValueError, TypeError, Hold, RecursionError,
            MemoryError, UnicodeError, csv.Error):
        print("HOLD: PRIVATE HUMAN all-pairs interval matrix not admitted",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
