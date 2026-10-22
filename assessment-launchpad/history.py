#!/usr/bin/env python3
"""Offline PRIVATE chronological-*proposal* HUMAN review history for LightUp Launchpad.

This is manually ordered HUMAN planning, not authenticated chronology, consent,
an assessment, a target interaction, a verification of remediation or a release.
No network, subprocess, DNS, model calls, or active targets.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
from html import escape
import json
import os
import sys

from launchpad import (
    FLAGS, Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold,
)
from review_desk import ROLES, STAGES, read_original_bundle
from compare_review import read_round

MIN_ROUNDS = 2
MAX_ROUNDS = 8
MAX_OUTPUT_ITEM_BYTES = 524_288
NAMES = (
    "lightup-lab-human-history-private.html",
    "lightup-lab-human-history-routing-private.csv",
    "lightup-lab-human-history-counts.json",
    "lightup-lab-human-history-counts.csv",
    "lightup-lab-human-history-brief.html",
)
STYLE = ("body{font:15px/1.55 system-ui,sans-serif;color:#17212f;"
         "background:#f5f7fa;max-width:1160px;margin:2rem auto;padding:0 1rem}"
         "h1{font-size:2rem}.hold{padding:1rem;background:#fff3e2;"
         "border-left:6px solid #9b5917;font-weight:750}"
         "section{background:white;border:1px solid #d5dce6;padding:1rem;"
         "margin:1rem 0;border-radius:.6rem}"
         "table{border-collapse:collapse;width:100%;margin:1rem 0}"
         "th,td{border:1px solid #c4cedb;text-align:left;vertical-align:top;padding:.55rem}"
         "th{background:#e9eef5}details{margin:.75rem 0;padding:.6rem;"
         "border:1px solid #c5d2e0;border-radius:.4rem}"
         "summary{font-weight:750;cursor:pointer}summary:focus-visible{outline:3px solid #daa842}"
         "pre{white-space:pre-wrap;overflow-wrap:anywhere}"
         "code{overflow-wrap:anywhere}small{color:#49596a}"
         "@media print{body{margin:0;max-width:none}details>*{display:block!important}}")

def analyze(rounds, from_round=1, to_round=None):
    """Only self-reported HUMAN changes; do not infer true assessment state."""
    count = len(rounds[0]["human_rows"])
    last = len(rounds) if to_round is None else to_round
    if (type(from_round) is not int or type(last) is not int
            or not 1 <= from_round < last <= len(rounds)):
        raise Hold("HUMAN interval requires two ordered round ordinals within 2–8")
    aggregate = {
        "schema": "lightup.assessment_launchpad_human_history_counts.v1",
        "status": "REVIEW_ONLY",
        "sequence": "manually_ordered_not_authenticated_chronology",
        "source_reported_endpoint_count": count,
        "human_round_count": len(rounds),
        "round_counts": [],
        "transition_counts": [],
        "interval_counts": {},
        "current_human_stage_counts": {
            stage: sum(row["stage"] == stage for row in rounds[-1]["human_rows"])
            for stage in STAGES
        },
        "current_human_role_counts": {
            role: sum(row["role"] == role for row in rounds[-1]["human_rows"])
            for role in ROLES
        },
        "original_endpoint_values_embedded": False,
        "private_human_notes_embedded": False,
        "original_source_hash_embedded": False,
        "source_paths_embedded": False,
        "human_stage_not_approval": True,
        **{flag: False for flag in FLAGS},
    }
    for i, work in enumerate(rounds):
        rows = work["human_rows"]
        aggregate["round_counts"].append({
            "round_ordinal": i + 1,
            "by_stage": {stage: sum(row["stage"] == stage for row in rows) for stage in STAGES},
            "by_role": {role: sum(row["role"] == role for row in rows) for role in ROLES},
            "human_notes_present": sum(bool(row["note"]) for row in rows),
        })
        if i == 0:
            continue
        prior_rows = rounds[i - 1]["human_rows"]
        updates = {
            "from_round": i,
            "to_round": i + 1,
            "changed_slots": 0,
            "stage_changes": 0,
            "role_changes": 0,
            "private_note_changes": 0,
            "stage_transition_counts": {
                first + "_TO_" + second: 0
                for first in STAGES for second in STAGES
            },
        }
        for prev, cur in zip(prior_rows, rows):
            stage_change = prev["stage"] != cur["stage"]
            role_change = prev["role"] != cur["role"]
            note_change = prev["note"] != cur["note"]
            updates["changed_slots"] += bool(stage_change or role_change or note_change)
            updates["stage_changes"] += stage_change
            updates["role_changes"] += role_change
            updates["private_note_changes"] += note_change
            updates["stage_transition_counts"][prev["stage"] + "_TO_" + cur["stage"]] += 1
        aggregate["transition_counts"].append(updates)
    first_rows = rounds[from_round - 1]["human_rows"]
    final_rows = rounds[last - 1]["human_rows"]
    window = rounds[from_round - 1:last]
    interval = {
        "from_round": from_round,
        "to_round": last,
        "source_reported_slots": count,
        "net_changed_slots": 0,
        "net_stage_changes": 0,
        "net_role_changes": 0,
        "net_private_note_changes": 0,
        "human_stages_returned_to_first_value": 0,
        "human_roles_returned_to_first_value": 0,
        "distinct_stage_values_represent_review_only": True,
    }
    for index, (before, after) in enumerate(zip(first_rows, final_rows)):
        stage_changed = before["stage"] != after["stage"]
        role_changed = before["role"] != after["role"]
        note_changed = before["note"] != after["note"]
        interval["net_changed_slots"] += bool(stage_changed or role_changed or note_changed)
        interval["net_stage_changes"] += stage_changed
        interval["net_role_changes"] += role_changed
        interval["net_private_note_changes"] += note_changed
        if before["stage"] == after["stage"] and any(
                work["human_rows"][index]["stage"] != before["stage"] for work in window[1:-1]):
            interval["human_stages_returned_to_first_value"] += 1
        if before["role"] == after["role"] and any(
                work["human_rows"][index]["role"] != before["role"] for work in window[1:-1]):
            interval["human_roles_returned_to_first_value"] += 1
    aggregate["interval_counts"] = interval
    return aggregate

def render_history(rounds, endpoints, summary):
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    elements = []
    for i, endpoint in enumerate(endpoints):
        current = rounds[-1]["human_rows"][i]
        changed = sum(
            rounds[j]["human_rows"][i] != rounds[j - 1]["human_rows"][i]
            for j in range(1, len(rounds))
        )
        rows = []
        for j, work in enumerate(rounds):
            row = work["human_rows"][i]
            prev = rounds[j - 1]["human_rows"][i] if j else None
            marker = ("Initial HUMAN self-report" if prev is None else
                      "changed from prior HUMAN round" if prev != row else
                      "unchanged from prior HUMAN round")
            rows.append(
                "<tr><td>" + str(j + 1) + "</td><td>" + escape(row["stage"]) +
                "</td><td>" + escape(row["role"]) +
                "</td><td><pre>" + escape(row["note"]) + "</pre></td><td>" +
                escape(marker) + "</td></tr>"
            )
        elements.append(
            "<details id='slot-" + str(i + 1).zfill(2) + "'><summary>Original endpoint slot " + str(i + 1).zfill(2) +
            " — current HUMAN stage " + escape(current["stage"]) + " · role " +
            escape(current["role"]) + " · " + str(changed) +
            " manually ordered changes</summary><p>PRIVATE literal original lab URL: "
            "<code>" + escape(endpoint) + "</code></p>"
            "<table><thead><tr><th>Operator-order round</th><th>HUMAN stage</th>"
            "<th>Suggested reviewer role</th><th>PRIVATE HUMAN note</th>"
            "<th>Self-report change</th></tr></thead><tbody>" +
            "".join(rows) + "</tbody></table></details>"
        )
    attention = []
    # Current source-free vocabulary only; no attestation or inferred clearance.
    # The private document contains endpoint/notes further down, but this
    # navigation deliberately shows only fixed labels and original ordinals.
    for row in sorted(
        rounds[-1]["human_rows"],
        key=lambda item: (
            STAGES.index(item["stage"]),
            ROLES.index(item["role"]),
            item["slot"],
        ),
    ):
        if row["stage"] not in ("NEEDS_INPUT", "FOLLOW_UP"):
            continue
        slot = str(row["slot"]).zfill(2)
        attention.append(
            "<tr><td><a href='#slot-" + slot + "'>Original slot " + slot +
            "</a></td><td>" + escape(row["stage"]) +
            "</td><td>" + escape(row["role"]) +
            "</td><td>" + str(len(row["note"])) + "</td></tr>"
        )
    workload_rows = []
    for item in summary["round_counts"]:
        workload_rows.append(
            "<tr><td>" + str(item["round_ordinal"]) + "</td>" +
            "".join("<td>" + str(item["by_stage"][stage]) + "</td>" for stage in STAGES) +
            "<td>" + str(item["human_notes_present"]) + "</td></tr>"
        )
    interval_rows = []
    window_from = summary["interval_counts"]["from_round"]
    window_to = summary["interval_counts"]["to_round"]
    for index in range(len(endpoints)):
        before = rounds[window_from - 1]["human_rows"][index]
        after = rounds[window_to - 1]["human_rows"][index]
        intermediate = rounds[window_from:window_to - 1]
        stage_return = (
            before["stage"] == after["stage"]
            and any(x["human_rows"][index]["stage"] != before["stage"] for x in intermediate)
        )
        role_return = (
            before["role"] == after["role"]
            and any(x["human_rows"][index]["role"] != before["role"] for x in intermediate)
        )
        if (before["stage"], before["role"], before["note"]) == (
                after["stage"], after["role"], after["note"]) and not (stage_return or role_return):
            continue
        slot = str(index + 1).zfill(2)
        interval_rows.append(
            "<tr><td><a href='#slot-" + slot + "'>Slot " + slot + "</a></td><td>" +
            escape(before["stage"]) + " → " + escape(after["stage"]) +
            "</td><td>" + escape(before["role"]) + " → " +
            escape(after["role"]) + "</td><td>" +
            ("YES" if before["note"] != after["note"] else "NO") +
            "</td><td>" + ("YES" if stage_return else "NO") +
            "</td><td>" + ("YES" if role_return else "NO") + "</td></tr>"
        )
    transitions = []
    for item in summary["transition_counts"]:
        transitions.append(
            "<tr><td>" + str(item["from_round"]) + " → " + str(item["to_round"]) +
            "</td><td>" + str(item["changed_slots"]) + "</td><td>" +
            str(item["stage_changes"]) + "</td><td>" + str(item["role_changes"]) +
            "</td><td>" + str(item["private_note_changes"]) + "</td></tr>"
        )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " style-src 'sha256-" + style_hash +
        "'; script-src 'none'; connect-src 'none'; img-src 'none';"
        " object-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp · PRIVATE HUMAN multi-round history</title><style>" +
        STYLE + "</style></head><body>"
        "<h1>Source-bound HUMAN review history</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "
        "REVIEW_ONLY · NOT AUTHORIZED</p>"
        "<p>" + str(len(rounds)) + " operator-ordered HUMAN rounds across " +
        str(len(endpoints)) + " original declared local lab endpoints. "
        "The selected order is NOT authenticated chronology and these are "
        "HUMAN self-reports, not tested findings, consent, authorization, "
        "remediation evidence or HUMAN GO.</p>"
        "<section><h2>Operator-selected HUMAN workload by round</h2>"
        "<table><thead><tr><th>Manual round</th>" +
        "".join("<th>" + escape(stage) + "</th>" for stage in STAGES) +
        "<th>Rows containing HUMAN notes</th></tr></thead><tbody>" +
        "".join(workload_rows) + "</tbody></table></section>"
        "<section><h2>Current HUMAN attention queue</h2>"
        "<p>Self-reported NEEDS_INPUT/FOLLOW_UP only. The link opens that "
        "endpoint's PRIVATE history below; no approval or clearance implied.</p>"
        "<table><thead><tr><th>Original slot</th><th>HUMAN stage</th>"
        "<th>Suggested role</th><th>Note characters</th></tr></thead><tbody>" +
        "".join(attention) + "</tbody></table></section>"
        "<section><h2>Manually selected HUMAN interval comparison: round " +
        str(window_from) + " → " + str(window_to) + "</h2>"
        "<p>Only HUMAN stage, role, note-change and temporary return-to-prior-value "
        "are compared. A stage returning to its earlier value is NOT a verified "
        "repair, relapse, severity change, clearance or authenticated chronology.</p>"
        "<table><thead><tr><th>Original slot</th><th>Stage interval</th>"
        "<th>Reviewer-role interval</th><th>Note changed?</th>"
        "<th>Stage returned?</th><th>Role returned?</th></tr></thead><tbody>" +
        "".join(interval_rows) + "</tbody></table></section>"
        "<section><h2>Human follow-up activity between adjacent rounds</h2>"
        "<table><thead><tr><th>Manual order</th><th>Changed slots</th>"
        "<th>Stages changed</th><th>Roles changed</th>"
        "<th>PRIVATE notes changed</th></tr></thead><tbody>" +
        "".join(transitions) + "</tbody></table></section>"
        "<section><h2>Private endpoint-by-endpoint HUMAN history</h2>"
        "<p>Expand each original slot. This PRIVATE local document contains "
        "original URLs and HUMAN note texts: do not host, publish or share.</p>" +
        "".join(elements) + "</section>"
        "<p><small>Original URL admission and source-byte consistency were "
        "rechecked without DNS, network or executing any assessment. "
        "Unsigned local review files do not authenticate the original producer "
        "or satisfy true scope permission, security/privacy review, action-time "
        "revocation or explicit HUMAN GO.</small></p></body></html>"
    ).encode("utf-8")


BRIEF_STYLE = (
    "body{background:#f4f7fa;color:#17212f;font:15px/1.55 system-ui,sans-serif;"
    "max-width:1020px;margin:2rem auto;padding:0 1rem}"
    "h1{font-size:2rem}.warning{background:#fff5e9;border-left:6px solid #a05a17;"
    "font-weight:750;padding:1rem}section{background:white;border:1px solid #cfd9e5;"
    "border-radius:.6rem;margin:1rem 0;padding:1rem}"
    "table{border-collapse:collapse;width:100%}th,td{text-align:left;"
    "border:1px solid #bfcbd9;padding:.65rem}th{background:#eff3f8}"
    "small{color:#475569}@media print{body{margin:0;max-width:none}}"
)

def render_counts_brief(summary):
    """Private-by-default source-free HUMAN workload overview; no original per-slot data."""
    css_hash = base64.b64encode(sha256(BRIEF_STYLE.encode("utf-8")).digest()).decode("ascii")
    rounds = []
    for record in summary["round_counts"]:
        rounds.append("<tr><td>" + str(record["round_ordinal"]) + "</td>" +
                      "".join("<td>" + str(record["by_stage"][stage]) + "</td>"
                              for stage in STAGES) +
                      "<td>" + str(record["human_notes_present"]) + "</td></tr>")
    transitions = []
    for record in summary["transition_counts"]:
        transitions.append(
            "<tr><td>" + str(record["from_round"]) + " → " +
            str(record["to_round"]) + "</td><td>" +
            str(record["changed_slots"]) + "</td><td>" +
            str(record["stage_changes"]) + "</td><td>" +
            str(record["role_changes"]) + "</td><td>" +
            str(record["private_note_changes"]) + "</td></tr>"
        )
    interval = summary["interval_counts"]
    current_roles = "".join(
        "<tr><td>" + escape(role) + "</td><td>" +
        str(summary["current_human_role_counts"][role]) + "</td></tr>"
        for role in ROLES
    )
    rows = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " style-src 'sha256-" + css_hash +
        "'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none';"
        " base-uri 'none'; form-action 'none'\">"
        "<title>LightUp HUMAN planning · counts only</title><style>" +
        BRIEF_STYLE + "</style></head><body>"
        "<h1>HUMAN planning · aggregate briefing</h1>"
        "<p class='warning'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY · "
        "DRAFT/HOLD · NO AUTHORIZATION</p>"
        "<p>Manually ordered HUMAN rounds: <strong>" +
        str(summary["human_round_count"]) +
        "</strong>; source-reported local slots: <strong>" +
        str(summary["source_reported_endpoint_count"]) +
        "</strong>. Stage and reviewer role are HUMAN self-reports only.</p>"
        "<section><h2>Follow-up workload per manually selected round</h2>"
        "<table><thead><tr><th>Round</th>" +
        "".join("<th>" + escape(stage) + "</th>" for stage in STAGES) +
        "<th>Notes present</th></tr></thead><tbody>" +
        "".join(rounds) + "</tbody></table></section>"
        "<section><h2>Changes between neighboring HUMAN rounds</h2>"
        "<table><thead><tr><th>Manual order</th><th>Changed slots</th>"
        "<th>Stage changes</th><th>Role changes</th>"
        "<th>Private notes modified</th></tr></thead><tbody>" +
        "".join(transitions) + "</tbody></table></section>"
        "<section><h2>Human interval comparison</h2>"
        "<p>Selected manual rounds " + str(interval["from_round"]) +
        " → " + str(interval["to_round"]) + ".</p>"
        "<table><tbody>"
        "<tr><th>Slots with net HUMAN changes</th><td>" +
        str(interval["net_changed_slots"]) + "</td></tr>"
        "<tr><th>Stage changes</th><td>" +
        str(interval["net_stage_changes"]) + "</td></tr>"
        "<tr><th>Role changes</th><td>" +
        str(interval["net_role_changes"]) + "</td></tr>"
        "<tr><th>Private note changes</th><td>" +
        str(interval["net_private_note_changes"]) + "</td></tr>"
        "<tr><th>Stage returned to previous HUMAN value</th><td>" +
        str(interval["human_stages_returned_to_first_value"]) + "</td></tr>"
        "<tr><th>Role returned to previous HUMAN value</th><td>" +
        str(interval["human_roles_returned_to_first_value"]) +
        "</td></tr></tbody></table></section>"
        "<section><h2>Latest suggested HUMAN reviewer distribution</h2>"
        "<table><thead><tr><th>Suggested reviewer role</th><th>Slots</th>"
        "</tr></thead><tbody>" + current_roles + "</tbody></table></section>"
        "<p><small>Only fixed vocabulary and aggregate integer counts appear here. "
        "Original endpoint URLs, source paths/digests, individual slot ordinals and "
        "private HUMAN note texts are not embedded. Small populations can still "
        "be identifiable from their counts; this briefing is PRIVATE by default "
        "and is NOT a confidentiality or anonymity guarantee. Manual order is "
        "not authenticated chronology. No real security findings, remediation, "
        "approvals, consent, grants, verified client identity, scans or HUMAN GO "
        "are attested by these self-reports.</small></p></body></html>"
    )
    return rows.encode("utf-8")

def output_artifacts(rounds, endpoints, from_round=1, to_round=None):
    summary = analyze(rounds, from_round, to_round)
    routing_rows = ["original_slot,current_human_stage,suggested_role,"
                    "note_character_count,changed_human_round_transitions"]
    for i, current in enumerate(rounds[-1]["human_rows"]):
        changed = sum(
            rounds[j]["human_rows"][i] != rounds[j - 1]["human_rows"][i]
            for j in range(1, len(rounds))
        )
        routing_rows.append(",".join((
            str(i + 1), current["stage"], current["role"], str(len(current["note"])),
            str(changed),
        )))
    summary_lines = ["kind,manual_round_or_transition,category,value,count"]
    for item in summary["round_counts"]:
        number = str(item["round_ordinal"])
        summary_lines += [
            "human_round," + number + ",stage," + stage + "," + str(value)
            for stage, value in item["by_stage"].items()
        ]
        summary_lines += [
            "human_round," + number + ",role," + role + "," + str(value)
            for role, value in item["by_role"].items()
        ]
        summary_lines.append("human_round," + number +
                             ",human_notes_present,all," + str(item["human_notes_present"]))
    for item in summary["transition_counts"]:
        label = str(item["from_round"]) + "_to_" + str(item["to_round"])
        summary_lines += [
            "human_transition," + label + ",count," + field + "," + str(item[field])
            for field in ("changed_slots", "stage_changes", "role_changes",
                          "private_note_changes")
        ]
        summary_lines += [
            "human_transition," + label + ",stage_transition," + key + "," + str(value)
            for key, value in item["stage_transition_counts"].items()
        ]
    interval = summary["interval_counts"]
    label = str(interval["from_round"]) + "_to_" + str(interval["to_round"])
    summary_lines += [
        "human_interval," + label + ",count," + key + "," + str(value)
        for key, value in interval.items()
        if key not in ("from_round", "to_round", "source_reported_slots",
                       "distinct_stage_values_represent_review_only")
    ]
    return [
        (NAMES[0], render_history(rounds, endpoints, summary)),
        (NAMES[1], ("\n".join(routing_rows) + "\n").encode("utf-8")),
        (NAMES[2], (json.dumps(summary, indent=2, ensure_ascii=False) + "\n").encode("utf-8")),
        (NAMES[3], ("\n".join(summary_lines) + "\n").encode("utf-8")),
        (NAMES[4], render_counts_brief(summary)),
    ]

def admitted_rounds(paths, digest, endpoints):
    if not MIN_ROUNDS <= len(paths) <= MAX_ROUNDS:
        raise Hold("history requires 2–8 operator-ordered source-bound HUMAN rounds")
    seen = set()
    directories, records = [], []
    for path in paths:
        directory, record = read_round(path, digest, endpoints)
        if directory in seen:
            raise Hold("cannot reuse a source round as a distinct HUMAN round")
        seen.add(directory)
        directories.append(directory)
        records.append(record)
    return directories, records

def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Review 2–8 original-source-bound manually ordered PRIVATE HUMAN rounds. "
        "No assessment, authorization or network I/O."))
    parser.add_argument("--bundle-dir", required=True,
                        help="original frozen-source five-file Launchpad packet")
    parser.add_argument("--round-dir", action="append", required=True,
                        help="PRIVATE HUMAN round, repeat 2–8 in manually selected order")
    parser.add_argument("--compare-from-round", type=int, default=1,
                        help="selected HUMAN interval first round ordinal (default 1)")
    parser.add_argument("--compare-to-round", type=int,
                        help="selected HUMAN interval final round ordinal (default latest)")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output-dir", help="NEW owner-only 0700 directory")
    destination.add_argument("--verify-history-dir", help="read-only reopen prior output")
    parser.add_argument("--explain-hold", action="store_true", help="print curated HOLD reason; raw paths, endpoint values and exceptions stay hidden")
    args = parser.parse_args(argv)
    try:
        source_dir, endpoints, digest = read_original_bundle(args.bundle_dir)
        round_dirs, rounds = admitted_rounds(args.round_dir, digest, endpoints)
        dest_fd, dest_dir = open_output_directory(args.output_dir or args.verify_history_dir)
        try:
            for source in [source_dir, *round_dirs]:
                if os.path.commonpath((source, dest_dir)) in (source, dest_dir):
                    raise Hold("history destination must be separate from source and rounds")
            expected = dict(output_artifacts(rounds, endpoints,
                                             args.compare_from_round, args.compare_to_round))
            if any(not 0 < len(data) <= MAX_OUTPUT_ITEM_BYTES
                   for data in expected.values()):
                raise Hold("bounded HUMAN history output capacity exceeded")
            if args.verify_history_dir:
                if set(os.listdir(dest_fd)) != set(NAMES):
                    raise Hold("PRIVATE history has missing or unexpected files")
                stored = {name: read_private_bundle_item(dest_fd, name, MAX_OUTPUT_ITEM_BYTES)
                          for name in NAMES}
                if stored != expected:
                    raise Hold("PRIVATE history files changed or source no longer matches")
            else:
                new_source, new_endpoints, new_digest = read_original_bundle(args.bundle_dir)
                new_dirs, new_rounds = admitted_rounds(args.round_dir, new_digest, new_endpoints)
                if ((new_source, new_endpoints, new_digest, new_dirs, new_rounds) !=
                        (source_dir, endpoints, digest, round_dirs, rounds)):
                    raise Hold("original or HUMAN rounds changed before history publication")
                publish_bundle(dest_fd, list(expected.items()))
        finally:
            os.close(dest_fd)
        print("PRIVATE_HUMAN_HISTORY_" + ("REOPENED" if args.verify_history_dir else "CREATED") +
              " round_count=" + str(len(rounds)) +
              " source_slot_count=" + str(len(endpoints)) +
              " — MANUAL ORDER, UNSIGNED, NO AUTHORIZATION OR EXECUTION")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HUMAN_HISTORY_HOLD — original source or private rounds not admitted", error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, UnicodeError, ImportError, OverflowError):
        report_hold("PRIVATE_HUMAN_HISTORY_HOLD — original source or private rounds not admitted", None, args.explain_hold)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
