#!/usr/bin/env python3
"""Owner-private HUMAN follow-up packs; never original source or authorization."""
from __future__ import annotations

import argparse
import csv
import html
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediation-portfolio"))
import portfolio
import action_board

ACTIONS = tuple(a for a in action_board.ACTION_CODES if a != "none")
QUESTIONS = {
    "request_fresh_source_export": "Can the original authorized owner supply a fresh current-source export?",
    "discuss_open_questions": "Which HUMAN questions require an original-source conversation?",
    "clarify_human_assignment": "Who should independently review this in the genuine authenticated original workflow?",
    "reconcile_anonymous_coverage": "Can the original source owner check possibly overlapping work without inferring case identity from numbers?",
    "request_original_human_review": "Can an independently authorized HUMAN reviewer inspect original evidence and record a real decision?",
}
WARNING = ("DRAFT/HOLD: locally self-declared source-free HUMAN counts, NOT authenticated "
           "findings, consent, source authority, verified remediation, scans, grants, "
           "retests or release. Anonymous ordinals and count differences do not identify "
           "clients, cases, vulnerabilities or fixes. Human original-source lookup required.")


def selected(rows, kind):
    priority = {"waiting_original_owner": 0, "needs_human_followup": 1,
                "not_triaged": 2, "locally_discussed": 3}
    return sorted((r for r in rows if r["local_followup_action_code"] == kind),
                  key=lambda r: (priority[r["local_planning_state_code"]],
                                 -r["unverified_pending_human_questions"],
                                 r["packet_ordinal_not_original_case"]))


def rollup(kind, rows):
    return {
        "action": kind,
        "packet_appearances_not_unique": len(rows),
        "unverified_questions_not_fixes": sum(r["unverified_pending_human_questions"]
                                             for r in rows),
        "local_state_counts": {
            s: sum(r["local_planning_state_code"] == s for r in rows)
            for s in action_board.STATE_CODES
        },
    }


def summary(groups, exposed_rows, only, ordinal):
    return {
        "kind": "lightup.private_human_action_handoff_counts_only",
        "schema_version": 1,
        "disposition": "LOCAL_HUMAN_PLANNING_DRAFT_HOLD_NO_AUTHORITY",
        "selected_packet_appearances_not_unique": len(exposed_rows),
        "no_action_appearances_excluded": (sum(
            r["local_followup_action_code"] == "none" for r in exposed_rows)
            if only is None else None),
        "single_local_ordinal_filter_not_original_identity": ordinal,
        "filtered_action": only or "all",
        "other_actions_omitted_not_zero": only is not None,
        "groups": [rollup(kind, rows) for kind, rows in groups.items()],
        "warning": WARNING,
        **{flag: False for flag in portfolio.FLAGS},
    }


def page(title, body):
    style = """<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#101b2d;color:#f1f8fa;padding:clamp(18px,4vw,50px);font:16px/1.6 system-ui}main{max-width:1100px;margin:auto}h1{line-height:1.2}a{color:#b2ede1}p{color:#d0dce5}aside,article{background:#203247;padding:20px;border-radius:14px;margin:20px 0}aside{border-left:5px solid #f4bd70}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;min-width:700px}th,td{border-bottom:1px solid #526174;text-align:left;padding:12px}@media print{body{background:white;color:black}aside,article{background:white;border:1px solid #333}p,a{color:#111}}</style>"""
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            '<title>' + html.escape(title) + '</title>' + style +
            '</head><body><main><small>LIGHTUP / PRIVATE / HUMAN ONLY / INCUBATE DRAFT HOLD</small>'
            '<h1>' + html.escape(title) + '</h1>' + body +
            '</main></body></html>').encode("utf-8")


def group_page(kind, rows):
    cells = []
    for row in rows:
        cells.append('<tr><th>%d</th><td>%s</td><td>%d</td><td>%d</td><td>%s</td></tr>' %
                     (row["packet_ordinal_not_original_case"],
                      html.escape(row["source_type"]),
                      row["anonymous_slot_appearances_not_unique"],
                      row["unverified_pending_human_questions"],
                      html.escape(action_board.DISPLAY[row["local_planning_state_code"]])))
    body = ('<aside><strong>NOT SENT, NOT VERIFIED.</strong><p>' +
            html.escape(WARNING) + '</p></aside>'
            '<article><h2>HUMAN source-owner question</h2><p>' +
            html.escape(QUESTIONS[kind]) + '</p></article>'
            '<p>Rows ordered by self-declared HUMAN waiting state, then question volume. '
            'This is NOT security severity, a real deadline or an original case list.</p>'
            '<div class="scroll"><table><thead><tr><th>Local ordinal, not a case</th>'
            '<th>Count source</th><th>Slots</th><th>Unverified questions</th>'
            '<th>Local state</th></tr></thead><tbody>' + ''.join(cells) +
            '</tbody></table></div><article><h2>Manual handoff only</h2><p>'
            'Independently re-open the original authenticated source, check its current '
            'human owner, actual status and separate permissions before any real work. '
            'These packets do not communicate with any other system.</p></article>'
            '<p><a href="index.html">Back to index</a></p>')
    return page(action_board.DISPLAY[kind], body)


def index_page(groups, metadata):
    entries = []
    for kind, rows in groups.items():
        label = html.escape(action_board.DISPLAY[kind])
        label = ('<a href="handoff-%s.html">%s</a>' % (kind, label)) if rows else label
        entries.append('<tr><td>%s</td><td>%d</td><td>%d</td></tr>' %
                       (label, len(rows),
                        sum(r["unverified_pending_human_questions"] for r in rows)))
    body = ('<aside><strong>NO AUTOMATIC DISPATCH.</strong><p>' +
            html.escape(WARNING) + '</p></aside><p>Current local action filter: <strong>' +
            html.escape(metadata["filtered_action"]) + '</strong>. No-action items '
            'are excluded, not resolved. Omitted groups are not zero.</p>'
            '<div class="scroll"><table><thead><tr><th>Local HUMAN action</th>'
            '<th>Anonymous packet appearances</th><th>Question appearances</th>'
            '</tr></thead><tbody>' + ''.join(entries) + '</tbody></table></div>'
            '<p>All documents stay on disk and can contain sensitive small-cell '
            'aggregates. They are PRIVATE 0600 but not encrypted at rest. '
            'Disclose only by deliberate authorized HUMAN choice.</p>')
    return page("Offline HUMAN follow-up handoff", body)


def action_csv(kind, rows):
    output = io.StringIO(newline="")
    csvout = csv.writer(output, lineterminator="\r\n")
    csvout.writerow(("local_ordinal_not_case", "source_count_type",
                     "slot_appearances_not_unique", "unverified_questions_not_fixes",
                     "human_action", "local_state"))
    for row in rows:
        csvout.writerow((row["packet_ordinal_not_original_case"],
                         row["source_type"],
                         row["anonymous_slot_appearances_not_unique"],
                         row["unverified_pending_human_questions"], kind,
                         row["local_planning_state_code"]))
    return output.getvalue().encode("ascii")


def action_brief(kind, rows):
    lines = ["LIGHTUP PRIVATE HUMAN HANDOFF / INCUBATE / DRAFT HOLD", WARNING,
             "", "Original HUMAN owner question:", QUESTIONS[kind], "",
             "Self-declared packet appearances (not unique cases): %d" % len(rows)]
    for row in rows:
        lines.append("Local ordinal %d: %d unverified question appearances; %s" %
                     (row["packet_ordinal_not_original_case"],
                      row["unverified_pending_human_questions"],
                      action_board.DISPLAY[row["local_planning_state_code"]]))
    lines.extend(("", "Manually verify actual original source and authorization.",
                  "Do not send automatically or interpret numbers as findings/fixes.", ""))
    return "\n".join(lines).encode("utf-8")


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def build(session_path, board_path, output_dir, only=None, ordinal=None):
    portfolio.require(only is None or only in ACTIONS)
    portfolio.require(ordinal is None or
                      (type(ordinal) is int and only in ACTIONS and 1 <= ordinal <= 12))
    portfolio.require(output_dir.is_absolute())
    portfolio.private_dir(output_dir.parent)
    portfolio.require(not output_dir.exists() and not output_dir.is_symlink())
    # Original producer-owned parsers perform strict bound/duplicate-key/flags,
    # private no-follow input and full ordinal/numeric-source equality admission.
    rows = action_board.board_import(board_path, session_path)
    if ordinal is not None:
        portfolio.require(ordinal <= len(rows) and
                          rows[ordinal - 1]["local_followup_action_code"] == only)
        exposed = [rows[ordinal - 1]]
    else:
        exposed = rows if only is None else [
            r for r in rows if r["local_followup_action_code"] == only]
    groups = {kind: selected(exposed, kind) for kind in ACTIONS
              if only is None or kind == only}
    meta = summary(groups, exposed, only, ordinal)
    stage = Path(tempfile.mkdtemp(dir=output_dir.parent,
                                  prefix=".lightup-human-handoff-"))
    os.chmod(stage, 0o700)
    try:
        portfolio.exclusive_write(stage / "index.html", index_page(groups, meta))
        portfolio.exclusive_write(stage / "handoff-summary.json",
                                  portfolio.serialize(meta))
        for kind, group in groups.items():
            if not group:
                continue
            portfolio.exclusive_write(stage / ("handoff-%s.html" % kind),
                                      group_page(kind, group))
            portfolio.exclusive_write(stage / ("handoff-%s.csv" % kind),
                                      action_csv(kind, group))
            portfolio.exclusive_write(stage / ("handoff-%s.txt" % kind),
                                      action_brief(kind, group))
        sync_directory(stage)
        portfolio.publish(stage, output_dir)  # Linux no-replace rename; never partial
        sync_directory(output_dir.parent)
        return meta
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=
        "Produce independent PRIVATE source-free HUMAN action packets, not sent/verified.")
    parser.add_argument("--session", required=True, type=Path,
                        help="Original owner-private 0600 saved browser session")
    parser.add_argument("--board", required=True, type=Path,
                        help="Exactly matched owner-private 0600 HUMAN action board")
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="New private output directory, no overwrite")
    parser.add_argument("--only", choices=ACTIONS,
                        help="Produce one action group's handoff to minimize disclosure")
    parser.add_argument("--ordinal", type=int,
                        help="With --only, disclose one exact selected local ordinal; never an original case ID")
    args = parser.parse_args()
    try:
        result = build(args.session, args.board, args.output_dir, args.only, args.ordinal)
    except (ValueError, OSError, RecursionError):
        print("HOLD: no complete private HUMAN handoff published.", file=sys.stderr)
        return 2
    print("Private HUMAN handoff prepared: %d action groups; not sent, not authorized." %
          len(result["groups"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
