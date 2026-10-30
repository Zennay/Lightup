"""PRIVATE source-free HUMAN revision history for one admitted original inbox board.

Never touches assessment targets, authorizes activity, authenticates actors,
assigns real owners or treats manually ordered snapshots as trusted chronology.
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
from human_review import Hold, source_bytes

MIN_ROUNDS = 2
MAX_ROUNDS = 8
OUTPUT_HTML = "PRIVATE-inbox-HUMAN-history.html"
OUTPUT_CSV = "PRIVATE-inbox-HUMAN-history.csv"
OUTPUT_JSON = "PRIVATE-inbox-HUMAN-history.json"
OUTPUT_ATTENTION_CSV = "PRIVATE-inbox-HUMAN-latest-attention.csv"
AUTHORITY_FLAGS = (
    "source_authenticated", "reviewers_authenticated",
    "chronology_authenticated", "client_consent_verified",
    "operator_consent_verified", "authorization_granted",
    "release_allowed", "signed",
)


def compose_history(originals: list[dict], revisions: list[list[dict]]) -> dict:
    """Build a complete privacy-minimal timeline from already admitted sheets."""
    if not MIN_ROUNDS <= len(revisions) <= MAX_ROUNDS:
        raise ValueError("2-8 original HUMAN revisions required")
    slots = [row["slot"] for row in originals]
    if not slots or len(slots) > actions.board.MAX_ROOMS:
        raise ValueError("original board slot membership refused")
    for revision in revisions:
        if len(revision) != len(slots) or [row["slot"] for row in revision] != slots:
            raise ValueError("history revision changed original membership")

    totals = []
    for index, revision in enumerate(revisions, 1):
        statuses = {key: 0 for key in actions.STATUSES}
        roles = {key: 0 for key in actions.ROLES}
        for row in revision:
            statuses[row["human_status"]] += 1
            roles[row["proposed_discussion_role"]] += 1
        totals.append({
            "round": index, "slots": len(slots),
            "human_status_counts": statuses, "proposed_role_counts": roles,
            "needs_input": statuses["NEEDS_INPUT"],
            "unreviewed": statuses["UNREVIEWED"],
            "discussion_complete_no_release": statuses["DISCUSSION_COMPLETE_NO_RELEASE"],
        })

    paths = []
    transitions = []
    for slot_index, slot in enumerate(slots):
        source = originals[slot_index]
        snapshots = []
        for index, revision in enumerate(revisions):
            row = revision[slot_index]
            snapshots.append({
                "round": index + 1, "human_status": row["human_status"],
                "proposed_role": row["proposed_discussion_role"],
            })
            if index == 0:
                continue
            previous = revisions[index - 1][slot_index]
            fields = []
            if previous["human_status"] != row["human_status"]:
                fields.append("human_status")
            if previous["proposed_discussion_role"] != row["proposed_discussion_role"]:
                fields.append("proposed_role")
            question_changed = previous["human_question"] != row["human_question"]
            next_changed = previous["human_next_action"] != row["human_next_action"]
            if question_changed:
                fields.append("question_text_changed")
            if next_changed:
                fields.append("next_action_text_changed")
            if fields:
                transitions.append({
                    "slot": slot, "from_round": index, "to_round": index + 1,
                    "changed_fields": fields,
                    "previous_status": previous["human_status"],
                    "current_status": row["human_status"],
                    "previous_role": previous["proposed_discussion_role"],
                    "current_role": row["proposed_discussion_role"],
                    "question_text_changed": question_changed,
                    "next_action_text_changed": next_changed,
                })
        paths.append({
            "slot": slot, "original_unselected_holds": source["unselected_hold"],
            "rounds": snapshots,
        })

    # HUMAN follow-up categories derive only from the last manually ordered
    # complete worksheet; they are neither actual routing nor risk severity.
    categories = {
        "NEEDS_INPUT": "HUMAN_INPUT_REQUESTED",
        "UNREVIEWED": "HUMAN_INITIAL_REVIEW",
        "IN_PROGRESS": "HUMAN_DISCUSSION_IN_PROGRESS",
        "DISCUSSION_COMPLETE_NO_RELEASE": "HUMAN_RECHECK_NO_RELEASE",
    }
    latest_attention = []
    for item in paths:
        last = item["rounds"][-1]
        latest_attention.append({
            "slot": item["slot"], "manual_round": len(revisions),
            "discussion_group": categories[last["human_status"]],
            "human_status": last["human_status"],
            "suggested_role": last["proposed_role"],
            "original_unselected_holds": item["original_unselected_holds"],
            "actual_owner_assigned": False, "release_allowed": False,
        })
    ranking = {status: index for index, status in enumerate(categories.values())}
    latest_attention.sort(key=lambda item: (ranking[item["discussion_group"]],
                                            item["slot"]))
    return {
        "schema": "lightup.private_human_inbox_history.v1",
        "status": "REVIEW_ONLY", "source_free": True,
        "original_board_byte_binding_checked": True,
        "complete_revision_membership_checked": True,
        "manual_order_not_authenticated_chronology": True,
        **{flag: False for flag in AUTHORITY_FLAGS},
        "slot_count": len(slots), "round_count": len(revisions),
        "round_summaries": totals, "slot_paths": paths,
        "changed_transitions": transitions, "latest_human_attention": latest_attention,
    }


def render_csv(history: dict) -> bytes:
    output = io.StringIO(newline="")
    columns = (
        "slot", "manual_round", "human_status", "proposed_role",
        "original_unselected_holds", "status_changed_since_previous",
        "role_changed_since_previous", "question_changed_since_previous",
        "next_action_changed_since_previous", "chronology_authenticated",
        "source_authenticated", "authorization_granted", "release_allowed",
    )
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(columns)
    for item in history["slot_paths"]:
        slot = item["slot"]
        path = item["rounds"]
        for index, row in enumerate(path):
            # The full note strings never enter any CSV, HTML or JSON output.
            # Compare the already minimized flags, never embed note contents.
            changed = next((change for change in history["changed_transitions"]
                            if change["slot"] == slot and
                            change["to_round"] == row["round"]), None)
            fields = changed["changed_fields"] if changed else []
            writer.writerow((
                slot, row["round"], row["human_status"], row["proposed_role"],
                item["original_unselected_holds"],
                str("human_status" in fields).lower(),
                str("proposed_role" in fields).lower(),
                str("question_text_changed" in fields).lower(),
                str("next_action_text_changed" in fields).lower(),
                "false", "false", "false", "false",
            ))
    return output.getvalue().encode("utf-8")


def render_attention_csv(history: dict) -> bytes:
    output = io.StringIO(newline="")
    fields = ("slot", "manual_round", "discussion_group", "human_status",
              "suggested_role", "original_unselected_holds",
              "actual_owner_assigned", "source_authenticated",
              "chronology_authenticated", "release_allowed")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(fields)
    for item in history["latest_human_attention"]:
        writer.writerow((
            item["slot"], item["manual_round"], item["discussion_group"],
            item["human_status"], item["suggested_role"],
            item["original_unselected_holds"], "false", "false", "false", "false",
        ))
    return output.getvalue().encode("utf-8")


def render_html(history: dict) -> bytes:
    escape = lambda value: html.escape(str(value), quote=True)
    rows = []
    for item in history["slot_paths"]:
        snapshots = " → ".join(
            f'R{r["round"]}: {escape(r["human_status"])} / {escape(r["proposed_role"])}'
            for r in item["rounds"]
        )
        rows.append(
            "<tr><th scope='row'>" + escape(item["slot"]) + "</th><td>" +
            escape(item["original_unselected_holds"]) + "</td><td>" +
            snapshots + "</td></tr>"
        )
    transition_rows = []
    for change in history["changed_transitions"]:
        transition_rows.append(
            "<tr>" + "".join("<td>" + escape(value) + "</td>" for value in (
                change["slot"], str(change["from_round"]) + " → " + str(change["to_round"]),
                ", ".join(change["changed_fields"]), change["current_status"],
                change["current_role"],
            )) + "</tr>"
        )
    attention_rows = []
    for item in history["latest_human_attention"]:
        attention_rows.append("<tr>" + "".join(
            "<td>" + escape(value) + "</td>"
            for value in (item["slot"], item["discussion_group"],
                          item["human_status"], item["suggested_role"],
                          item["original_unselected_holds"])
        ) + "</tr>")
    summaries = []
    for round_ in history["round_summaries"]:
        summaries.append("<tr>" + "".join(
            "<td>" + escape(value) + "</td>"
            for value in (round_["round"], round_["slots"], round_["unreviewed"],
                          round_["needs_input"], round_["discussion_complete_no_release"])
        ) + "</tr>")
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRIVATE HUMAN revision history</title>
<style>body{font:16px/1.5 system-ui;margin:2rem auto;padding:1rem;max-width:1180px;color:#1b2b3e}
table{width:100%;border-collapse:collapse;margin:1.2rem 0}th,td{border:1px solid #aeb8c7;padding:.65rem;text-align:left;overflow-wrap:anywhere;vertical-align:top}
th{background:#e8f0f8}.warning{background:#fff0dd;border-left:5px solid #956000;padding:1rem}
@media print{body{margin:0;padding:0}tr{break-inside:avoid}}</style></head><body>
<h1>PRIVATE HUMAN revision history</h1>
<p class="warning">REVIEW_ONLY / HOLD · INCUBATE M3/M7 PLAN/LAB ONLY. Snapshot order was
manually supplied and is NOT authenticated chronology. Suggested roles are NOT actual
assignments; completed discussion is NOT a fixed finding, verified source, permission,
client/operator consent, security review or authorization to scan, dispatch or release.
All original evidence and current HUMAN choices remain unchanged. Keep this private.</p>
<h2>Discussion progress (declared, not verified)</h2>
<table><thead><tr><th>Manual round</th><th>Slots</th><th>Unreviewed</th><th>Needs input</th><th>Discussion complete / no release</th></tr></thead><tbody>__SUMMARY__</tbody></table>
<h2>Latest manual HUMAN follow-up (no automatic routing)</h2>
<p>Includes all original slots, even completed discussion without release.
Proposed roles are never actual staff assignments or verified deadlines.</p>
<table><thead><tr><th>Slot</th><th>Follow-up category</th><th>Latest stage</th><th>Suggested role</th><th>Original HOLD choices</th></tr></thead><tbody>__ATTENTION__</tbody></table>
<h2>Per-slot progress</h2>
<table><thead><tr><th>Original order slot</th><th>Original unresolved choices</th><th>Manually ordered HUMAN stage / proposed role</th></tr></thead><tbody>__PATHS__</tbody></table>
<h2>Changes between adjacent rounds</h2>
<p>No question or next-action text is included; only changed-field names are reported.</p>
<table><thead><tr><th>Slot</th><th>Manual transition</th><th>Changed fields</th><th>Latest stage</th><th>Latest suggested role</th></tr></thead><tbody>__CHANGES__</tbody></table>
<p>Blank change rows indicate equal accepted fields for adjacent rounds, never a remediation verdict.
Slots refer to manual original board order, not identity. All data is source-free but not necessarily anonymous.
This unsigned local custody report has no trusted history or identity proof.</p></body></html>"""
    return (page.replace("__SUMMARY__", "".join(summaries))
                .replace("__ATTENTION__", "".join(attention_rows))
                .replace("__PATHS__", "".join(rows))
                .replace("__CHANGES__", "".join(transition_rows)
                         or "<tr><td colspan='5'>No HUMAN planning changes</td></tr>")
                .encode("utf-8"))


def artifacts_for(history: dict) -> list[tuple[str, bytes]]:
    return [
        (OUTPUT_HTML, render_html(history)),
        (OUTPUT_CSV, render_csv(history)),
        (OUTPUT_ATTENTION_CSV, render_attention_csv(history)),
        (OUTPUT_JSON, (json.dumps(history, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True) + "\n").encode("utf-8")),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Source-free PRIVATE HUMAN revision history; no assessment execution")
    parser.add_argument("action", choices=("build", "reopen",
                                           "receive-browser", "reopen-browser"))
    parser.add_argument("--board", required=True, help="exact original source-free PRIVATE board JSON")
    parser.add_argument("--revision", action="append", required=True,
                        help="one complete private HUMAN CSV, repeat in manual order 2-8 times")
    parser.add_argument("--private-output-dir", required=True,
                        help="fresh empty 0700 directory for build, exact saved 0700 directory for reopen")
    parser.add_argument("--browser-history",
                        help="owner-only 0600 source-free browser history JSON; required for receive-browser/reopen-browser")
    args = parser.parse_args()
    try:
        if not MIN_ROUNDS <= len(args.revision) <= MAX_ROUNDS:
            raise ValueError("2-8 complete HUMAN revision files required")
        browser_mode = args.action in ("receive-browser", "reopen-browser")
        if browser_mode != (args.browser_history is not None):
            raise ValueError("browser history input allowed only for explicit browser receive/reopen")
        board_raw = source_bytes(args.board)
        digest, originals = actions.board_admit(args.board)
        if digest != hashlib.sha256(board_raw).hexdigest():
            raise ValueError("original board changed during admission")
        original_raws = [source_bytes(path) for path in args.revision]
        if len(set(original_raws)) != len(original_raws):
            raise ValueError("duplicate HUMAN revision bytes are ambiguous")
        revisions = [actions.read_human_csv(path, digest, originals)
                     for path in args.revision]
        history = compose_history(originals, revisions)
        browser_raw = None
        if browser_mode:
            # Browser-generated JSON is unsigned. Admit only its exact canonical
            # source-free content, rebuilt from the unchanged ORIGINAL native
            # board and every complete original HUMAN CSV worksheet.
            browser_raw = source_bytes(args.browser_history)
            browser_data = json.loads(
                browser_raw.decode("utf-8", "strict"),
                object_pairs_hook=actions.unique,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    ValueError("invalid browser JSON constant")))
            canonical = lambda doc: json.dumps(
                doc, ensure_ascii=True, sort_keys=True,
                separators=(",", ":")).encode("utf-8")
            if canonical(browser_data) != canonical(history):
                raise ValueError("browser history differs from exact admitted original HUMAN revisions")
        artifacts = artifacts_for(history)
        # Repeat original private input-byte admission before output publication
        # or reopen, rejecting any concurrent original board/HUMAN file drift.
        if source_bytes(args.board) != board_raw:
            raise ValueError("original board bytes changed during history")
        for path, raw in zip(args.revision, original_raws):
            if source_bytes(path) != raw:
                raise ValueError("original HUMAN revision changed during history")
        # Never publish inside a directory holding the original PRIVATE board
        # or HUMAN revisions; an extra report folder poisons exact admission.
        admitted_inputs = [args.board, *args.revision]
        if browser_mode:
            admitted_inputs.append(args.browser_history)
        for original_path in admitted_inputs:
            actions.board.require_output_outside_source_tree(
                os.path.dirname(os.path.realpath(original_path)),
                args.private_output_dir)
        if browser_mode and source_bytes(args.browser_history) != browser_raw:
            raise ValueError("browser history bytes changed during source admission")
        if args.action in ("build", "receive-browser"):
            actions.publish_private_artifacts(args.private_output_dir, artifacts)
        else:
            actions.reopen_private_artifacts(args.private_output_dir, artifacts)
        print("REVIEW_ONLY: PRIVATE HUMAN manually ordered history", args.action,
              "complete; no chronology, consent, assessment or release")
        return 2
    except (ValueError, OSError, TypeError, Hold, MemoryError, UnicodeError,
            RecursionError, csv.Error):
        print("HOLD: PRIVATE HUMAN source-bound revision history not admitted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
