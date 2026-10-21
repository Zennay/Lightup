"""Original PRIVATE HUMAN multi-round interval dossier; HUMAN coordination only.

No target access, scans, permissions, signed history, consent, remediation or
release authority is created by this unsigned source-bound local report.
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
from human_review import Hold, source_bytes

OUTPUT_HTML = "PRIVATE-HUMAN-original-interval.html"
OUTPUT_CSV = "PRIVATE-HUMAN-original-interval.csv"
OUTPUT_JSON = "PRIVATE-HUMAN-original-interval.json"
FALSE_FLAGS = (
    "source_authenticated", "reviewers_authenticated",
    "chronology_authenticated", "client_consent_verified",
    "operator_consent_verified", "authorization_granted",
    "release_allowed", "signed",
)
ROW_KEYS = (
    "slot", "from_status", "to_status", "status_endpoint_changed",
    "status_edited_within_interval", "from_proposed_role", "to_proposed_role",
    "proposed_role_endpoint_changed", "role_edited_within_interval",
    "question_edited_within_interval", "next_action_edited_within_interval",
    "original_unselected_holds",
)


def compose_interval(complete_history: dict, start: int, end: int) -> dict:
    if type(start) is not int or type(end) is not int or not (
        1 <= start < end <= complete_history["round_count"]
    ):
        raise ValueError("interval must be earlier/later original HUMAN rounds")
    changes = complete_history["changed_transitions"]
    rows = []
    for source in complete_history["slot_paths"]:
        earlier = source["rounds"][start - 1]
        later = source["rounds"][end - 1]
        fields = {
            field for change in changes
            if change["slot"] == source["slot"] and
            start < change["to_round"] <= end
            for field in change["changed_fields"]
        }
        rows.append({
            "slot": source["slot"],
            "from_status": earlier["human_status"],
            "to_status": later["human_status"],
            "status_endpoint_changed":
                earlier["human_status"] != later["human_status"],
            "status_edited_within_interval": "human_status" in fields,
            "from_proposed_role": earlier["proposed_role"],
            "to_proposed_role": later["proposed_role"],
            "proposed_role_endpoint_changed":
                earlier["proposed_role"] != later["proposed_role"],
            "role_edited_within_interval": "proposed_role" in fields,
            "question_edited_within_interval": "question_text_changed" in fields,
            "next_action_edited_within_interval":
                "next_action_text_changed" in fields,
            "original_unselected_holds": source["original_unselected_holds"],
        })
    active = sum(any(row[field] for field in (
        "status_edited_within_interval", "role_edited_within_interval",
        "question_edited_within_interval", "next_action_edited_within_interval",
    )) for row in rows)
    return {
        "schema": "lightup.private_human_original_interval.v1",
        "status": "REVIEW_ONLY",
        "source_free": True,
        "original_complete_input_reopening_required": True,
        "manual_order_not_authenticated_chronology": True,
        **{flag: False for flag in FALSE_FLAGS},
        "manual_start_round": start,
        "manual_end_round": end,
        "original_slot_count": complete_history["slot_count"],
        "original_round_count": complete_history["round_count"],
        "slots_with_any_declared_human_field_activity": active,
        "all_original_slots": rows,
    }


def render_csv(report: dict) -> bytes:
    dest = io.StringIO(newline="")
    writer = csv.writer(dest, lineterminator="\n")
    header = (
        *ROW_KEYS, "manual_start_round", "manual_end_round",
        "source_authenticated", "chronology_authenticated",
        "authorization_granted", "release_allowed",
    )
    writer.writerow(header)
    for row in report["all_original_slots"]:
        writer.writerow([
            str(row[key]).lower() if type(row[key]) is bool else row[key]
            for key in ROW_KEYS
        ] + [
            report["manual_start_round"], report["manual_end_round"],
            "false", "false", "false", "false",
        ])
    return dest.getvalue().encode("utf-8")


def render_html(report: dict) -> bytes:
    esc = lambda value: html.escape(str(value), quote=True)
    headings = (
        "Original slot", "Prior HUMAN stage", "Later HUMAN stage",
        "Stage differs at endpoints", "Stage edited during interval",
        "Prior proposed role", "Later proposed role", "Role differs at endpoints",
        "Role edited during interval", "Question edited at least once",
        "Next action edited at least once", "Original HOLD choices",
    )
    vals = (
        "slot", "from_status", "to_status", "status_endpoint_changed",
        "status_edited_within_interval", "from_proposed_role",
        "to_proposed_role", "proposed_role_endpoint_changed",
        "role_edited_within_interval", "question_edited_within_interval",
        "next_action_edited_within_interval", "original_unselected_holds",
    )
    lines = []
    for row in report["all_original_slots"]:
        lines.append("<tr>" + "".join(
            "<td>" + esc(str(row[key]).lower() if type(row[key]) is bool else row[key])
            + "</td>" for key in vals
        ) + "</tr>")
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRIVATE HUMAN original discussion interval</title>
<style>body{font:16px/1.5 system-ui;max-width:1250px;margin:2rem auto;padding:1rem;color:#20314a}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #abc0d5;padding:.45rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#edf4fb} .warning{border-left:5px solid #8c5900;background:#fff1dd;padding:1rem}
@media print{body{margin:0;font-size:12px}tr{break-inside:avoid}}</style></head><body>
<h1>PRIVATE HUMAN original discussion interval</h1>
<p class="warning"><strong>REVIEW_ONLY / HOLD · INCUBATE M3/M7 PLAN/LAB ONLY.</strong>
HUMAN snapshots are manually ordered and NOT authenticated timestamps.
Original status/role edits can be reversed; an intermediate note edit is
NOT proof that final note content changed. Proposed roles are NOT assignments,
a complete discussion is NOT remediation, and no security review, consent,
source identity, target clearance, grant or release is established.
This report is unsigned local custody ONLY. Keep private.</p>
<p>Comparing manually selected rounds: <strong>__START__ → __END__</strong>.
Original slots: <strong>__SLOTS__</strong>. Slots with reported HUMAN field
activity in this interval: <strong>__ACTIVE__</strong>.</p>
<table><thead><tr>__HEADINGS__</tr></thead><tbody>__ROWS__</tbody></table>
<p>All original slots remain listed; original note text, source targets, file
paths, full board SHA and real reviewer identifiers are deliberately omitted.
Local source-byte equality is NOT external provenance or authorization.
The unchanged original source-owner, security/privacy/browser reviews,
current separately authenticated client/operator consent with action-time
revocation, #177/#182/#829 and explicit HUMAN GO remain mandatory.
No customer contact, scan, dispatch or release follows from this report.</p>
</body></html>"""
    return (page.replace("__START__", esc(report["manual_start_round"]))
                .replace("__END__", esc(report["manual_end_round"]))
                .replace("__SLOTS__", esc(report["original_slot_count"]))
                .replace("__ACTIVE__", esc(report["slots_with_any_declared_human_field_activity"]))
                .replace("__HEADINGS__", "".join(
                    "<th scope='col'>" + esc(label) + "</th>" for label in headings))
                .replace("__ROWS__", "".join(lines)).encode("utf-8"))


def expected_artifacts(report: dict) -> list[tuple[str, bytes]]:
    return [
        (OUTPUT_HTML, render_html(report)),
        (OUTPUT_CSV, render_csv(report)),
        (OUTPUT_JSON, (json.dumps(
            report, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ) + "\n").encode("utf-8")),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Original-source private HUMAN interval, no assessment execution"
    )
    parser.add_argument("action", choices=("build", "reopen"))
    parser.add_argument("--board", required=True)
    parser.add_argument("--revision", action="append", required=True)
    parser.add_argument("--from-round", type=int, required=True)
    parser.add_argument("--to-round", type=int, required=True)
    parser.add_argument("--private-output-dir", required=True)
    args = parser.parse_args()
    try:
        if not timeline.MIN_ROUNDS <= len(args.revision) <= timeline.MAX_ROUNDS:
            raise ValueError("2–8 complete original HUMAN revisions required")
        board_raw = source_bytes(args.board)
        board_digest, originals = actions.board_admit(args.board)
        if hashlib.sha256(board_raw).hexdigest() != board_digest:
            raise ValueError("original board changed during admission")
        csv_bytes = [source_bytes(path) for path in args.revision]
        if len(set(csv_bytes)) != len(csv_bytes):
            raise ValueError("duplicate complete original HUMAN revisions refused")
        revisions = [
            actions.read_human_csv(path, board_digest, originals)
            for path in args.revision
        ]
        report = compose_interval(
            timeline.compose_history(originals, revisions),
            args.from_round, args.to_round,
        )
        artifacts = expected_artifacts(report)
        # Keep any output outside all original directories.
        for source in (args.board, *args.revision):
            actions.board.require_output_outside_source_tree(
                os.path.dirname(os.path.realpath(source)), args.private_output_dir
            )
        if source_bytes(args.board) != board_raw:
            raise ValueError("board changed before interval publication")
        for path, previous in zip(args.revision, csv_bytes):
            if source_bytes(path) != previous:
                raise ValueError("HUMAN worksheet changed before publication")
        if args.action == "build":
            actions.publish_private_artifacts(args.private_output_dir, artifacts)
        else:
            actions.reopen_private_artifacts(args.private_output_dir, artifacts)
        print("REVIEW_ONLY: PRIVATE HUMAN interval", args.action,
              "completed; no chronology, source, consent, scan or release")
        return 2
    except (OSError, ValueError, TypeError, Hold, RecursionError,
            MemoryError, UnicodeError, csv.Error):
        print("HOLD: original PRIVATE HUMAN discussion interval not admitted",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
