#!/usr/bin/env python3
"""PRIVATE offline source-bound HUMAN selection changes; never authority or chronology."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from hashlib import sha256
from html import escape
import json
import os
import sys

from action_handoff import read_selected, selected_source_rows, WORK_CSV
from history import admitted_rounds
from launchpad import Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold
from review_desk import read_original_bundle, ROLES
from role_return_reconcile import admitted_replies, render_files

REPORT_HTML = "lightup-lab-human-selection-diff-private.html"
REPORT_CSV = "lightup-lab-human-selection-diff-private.csv"
REPORT_JSON = "lightup-lab-human-selection-diff-counts-private.json"
REPORT_GUIDE = "START-HERE-HUMAN-SELECTION-DIFF-PRIVATE.txt"
FILES = (REPORT_HTML, REPORT_CSV, REPORT_JSON, REPORT_GUIDE)
MAX_OUTPUT = 65536
STYLE = (
    "body{font:15px/1.5 system-ui,sans-serif;background:#f2f5fb;color:#182c43;"
    "max-width:1100px;margin:auto;padding:1.2rem}h1{font-size:1.9rem}"
    ".hold{border-left:5px solid #93531b;padding:1rem;background:#fff1df;font-weight:750}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));gap:.8rem}"
    ".grid div{background:white;border:1px solid #c5d4e2;padding:.8rem;border-radius:.5rem}"
    ".tablewrap{overflow-x:auto}table{background:white;border-collapse:collapse;width:100%}"
    "th,td{border:1px solid #c1d0e0;padding:.6rem;text-align:left}th{background:#e6effa}"
    "@media(max-width:700px){table{min-width:940px}}"
)
HEADER = ("original_slot", "selection_change", "latest_suggested_role",
          "private_human_reply_status", "latest_self_reported_human_stage",
          "suggested_operator_next_step", "private_note_changed")
FLAGS = {
    "identity_authenticated": False,
    "source_authority_authenticated": False,
    "client_operator_consent_verified": False,
    "authorization_granted": False,
    "dispatch_allowed": False,
    "human_go": False,
    "release_allowed": False,
}


def read_sources(args):
    bundle, endpoints, digest = read_original_bundle(args.bundle_dir)
    round_dirs, rounds = admitted_rounds(args.round_dir, digest, endpoints)
    replies = admitted_replies(args.role_return_dir, rounds, endpoints, digest)
    original_csv = render_files(replies, rounds, endpoints)[WORK_CSV]
    before_dir, before_bytes = read_selected(args.before_csv)
    after_dir, after_bytes = read_selected(args.after_csv)
    before, total = selected_source_rows(original_csv, before_bytes)
    after, other_total = selected_source_rows(original_csv, after_bytes)
    if total != other_total:
        raise Hold("PRIVATE selections have inconsistent original source counts")
    directories = (bundle, *round_dirs, *(reply[0] for reply in replies),
                   before_dir, after_dir)
    # Re-admit exact original packet, every original round and role return,
    # and both operator-supplied selected CSVs before any file publication.
    snapshot = (tuple(endpoints), digest, rounds, replies,
                before_bytes, after_bytes, before, after)
    return directories, snapshot, before, after, total


def summarize(before, after, total):
    first = {row[0]: row for row in before}
    last = {row[0]: row for row in after}
    all_slots = sorted(set(first) | set(last), key=lambda val: int(val))
    classified = []
    for slot in all_slots:
        # Each original slot occurs at most once in the unique ordered source.
        if slot in first and slot in last:
            kind = "UNCHANGED_SELECTION"
        elif slot in last:
            kind = "NEWLY_SELECTED"
        else:
            kind = "NO_LONGER_SELECTED"
        classified.append((slot, kind, *(last.get(slot) or first[slot])[1:]))
    counts = Counter(row[1] for row in classified)
    transitions_by_role = {
        role: {kind: sum(row[2] == role and row[1] == kind for row in classified)
               for kind in ("NEWLY_SELECTED", "NO_LONGER_SELECTED", "UNCHANGED_SELECTION")}
        for role in sorted({row[2] for row in classified})
    }
    transitions_by_next_action = {
        action: {kind: sum(row[5] == action and row[1] == kind for row in classified)
                 for kind in ("NEWLY_SELECTED", "NO_LONGER_SELECTED", "UNCHANGED_SELECTION")}
        for action in sorted({row[5] for row in classified})
    }
    data = {
        "schema": "lightup.private_human_selection_comparison.v1",
        "status": "REVIEW_ONLY",
        "original_local_slot_count": total,
        "before_selected_count": len(before),
        "after_selected_count": len(after),
        "newly_selected_count": counts["NEWLY_SELECTED"],
        "no_longer_selected_count": counts["NO_LONGER_SELECTED"],
        "unchanged_selection_count": counts["UNCHANGED_SELECTION"],
        "transition_counts_by_suggested_role": transitions_by_role,
        "transition_counts_by_suggested_human_action": transitions_by_next_action,
        "manually_supplied_order_is_not_chronology": True,
        "original_source_consistency_is_not_authentication": True,
        "source_paths_embedded": False,
        "endpoint_values_embedded": False,
        "private_note_text_embedded": False,
        **FLAGS,
    }
    return classified, data


def render(before, after, total, role_filter=None, all_role_counts=None):
    rows, summary = summarize(before, after, total)
    role_note = ""
    if role_filter is not None:
        if all_role_counts is None:
            raise Hold("role-only output needs original all-role counts")
        summary.update({
            "operator_suggested_role_filter": role_filter,
            "before_selected_all_roles_count": all_role_counts[0],
            "after_selected_all_roles_count": all_role_counts[1],
            "role_filtered_slot_count": len(rows),
            "role_filter_applied_after_full_source_admission": True,
            "role_filter_verifies_recipient_identity": False,
        })
        role_note = ("<p>Restricted to suggested HUMAN role: " +
                     escape(role_filter.replace("_", " ")) +
                     ". Before/after cards are role-only counts; all-role totals are " +
                     str(all_role_counts[0]) + " before and " +
                     str(all_role_counts[1]) + " after. This is NOT verified " +
                     "recipient identity or role assignment.</p>")
    cards = "".join("<div><strong>" + escape(label.replace("_", " ")) +
                    "</strong><br>" + str(summary[key]) + "</div>"
                    for label, key in (
                        ("Before selected", "before_selected_count"),
                        ("After selected", "after_selected_count"),
                        ("Newly selected", "newly_selected_count"),
                        ("No longer selected", "no_longer_selected_count"),
                        ("Unchanged selections", "unchanged_selection_count"),
                    ))
    def dimension_table(title, values):
        heads = ("NEWLY_SELECTED", "NO_LONGER_SELECTED", "UNCHANGED_SELECTION")
        content = "".join("<tr><th>" + escape(label.replace("_", " ")) + "</th>" +
                          "".join("<td>" + str(counts[kind]) + "</td>" for kind in heads)
                          + "</tr>" for label, counts in values.items())
        return ("<h2>" + escape(title) + "</h2><div class='tablewrap'>"
                + "<table><thead><tr><th>Fixed HUMAN category</th>"
                + "".join("<th>" + escape(h.replace("_", " ")) + "</th>" for h in heads)
                + "</tr></thead><tbody>" + content + "</tbody></table></div>")
    matrix = dimension_table("Selection membership by suggested HUMAN role",
                             summary["transition_counts_by_suggested_role"])
    matrix += dimension_table("Selection membership by suggested next HUMAN action",
                              summary["transition_counts_by_suggested_human_action"])
    table_rows = "".join("<tr>" + "".join(
        "<td>" + escape(cell.replace("_", " ")) + "</td>"
        for cell in row) + "</tr>" for row in rows)
    style_hash = base64.b64encode(sha256(STYLE.encode()).digest()).decode("ascii")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        + "style-src 'sha256-" + style_hash + "'; script-src 'none'; "
        + "connect-src 'none'; img-src 'none'; frame-src 'none'; "
        + "object-src 'none'; form-action 'none'; base-uri 'none'\">"
        + "<title>LightUp PRIVATE HUMAN selection comparison</title><style>"
        + STYLE + "</style></head><body>"
        + "<h1>PRIVATE HUMAN selection change desk</h1>"
        + "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY · "
        + "DRAFT/HOLD · NO AUTHORIZATION</p>"
        + "<p>The operator supplied two unsigned, local, original-source-bound "
        + "HUMAN selection CSVs. Their chosen order is not verified chronology, "
        + "role ownership or review. No source changes, scanning, consent, "
        + "remediation, grants, dispatch or HUMAN GO are inferred.</p>"
        + role_note
        + "<div class='grid'>" + cards + "</div>" + matrix
        + "<p>The rows below contain only PRIVATE original-local ordinals and "
        + "fixed HUMAN labels; small groups may still identify people. "
        + "Handle locally and share only with authorized recipients.</p>"
        + "<div class='tablewrap'><table><thead><tr>"
        + "".join("<th>" + escape(head.replace("_", " ")) + "</th>" for head in HEADER)
        + "</tr></thead><tbody>" + table_rows + "</tbody></table></div>"
        + "<p>Unselected slots in both files are intentionally omitted, not "
        + "verified completed. The packet is source-consistent, not authenticated. "
        + "No target, original source hash, original path or note is embedded.</p>"
        + "</body></html>"
    ).encode("utf-8")
    csv_lines = [",".join(HEADER)] + [",".join(row) for row in rows]
    csv_out = ("\r\n".join(csv_lines) + "\r\n").encode("utf-8")
    guide = (
        "LIGHTUP PRIVATE HUMAN SELECTION CHANGES — REVIEW_ONLY\n"
        "This local four-file packet compares two explicit, source-bound CSVs.\n"
        "Only original-local slot ordinals and fixed HUMAN enums are present.\n"
        "Operator order is not proven chronology. Unchanged means selected in\n"
        "both CSVs, not that source status or a finding was resolved.\n"
        "No source authentication, reviewer identity, consent, grant, scan,\n"
        "dispatch, remediation, release or HUMAN GO.\n"
        "The packet is owner-only 0600 / 0700 and contains PRIVATE identifiers.\n"
        "Reopen against the SAME original source bundle, HUMAN rounds, returns\n"
        "and both exact selected CSV files; no output changes are permitted.\n"
        + ("Optional proposed-role filtering never authenticates a recipient.\n"
           if role_filter is not None else "")
    ).encode("utf-8")
    payload = (html, csv_out,
               (json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n").encode(),
               guide)
    if any(not 0 < len(item) <= MAX_OUTPUT for item in payload):
        raise Hold("selected HUMAN diff output exceeds PRIVATE packet bound")
    return dict(zip(FILES, payload)), summary


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare two exact-source PRIVATE HUMAN selection CSVs offline")
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--round-dir", action="append", required=True)
    parser.add_argument("--role-return-dir", action="append", required=True)
    parser.add_argument("--before-csv", required=True)
    parser.add_argument("--after-csv", required=True)
    parser.add_argument("--suggested-role", choices=ROLES,
                        help="optional source-bound proposed HUMAN role-only packet; never authenticates a recipient")
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--output-dir", help="new empty owner-only 0700 folder")
    output.add_argument("--verify-output-dir", help="read-only reopen of prior 4-file packet")
    output.add_argument("--preview-only", action="store_true",
                        help="show counts from original-source-bound CSVs, write nothing")
    parser.add_argument("--explain-hold", action="store_true", help="print curated HOLD reason; raw paths, endpoint values and exceptions stay hidden")
    args = parser.parse_args(argv)
    try:
        source = read_sources(args)
        before, after = source[2:4]
        all_role_counts = (len(before), len(after))
        if args.suggested_role is not None:
            before = [row for row in before if row[1] == args.suggested_role]
            after = [row for row in after if row[1] == args.suggested_role]
            if not before and not after:
                raise Hold("no exact original selected HUMAN slots in proposed role")
        payload, summary = render(before, after, source[4], args.suggested_role,
                                 all_role_counts if args.suggested_role is not None else None)
        if args.preview_only:
            print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
            return 0
        fd, destination = open_output_directory(args.output_dir or args.verify_output_dir)
        try:
            for directory in source[0]:
                common = os.path.commonpath((directory, destination))
                if common in (directory, destination):
                    raise Hold("PRIVATE comparison output must be outside every original source")
            if args.verify_output_dir:
                if set(os.listdir(fd)) != set(FILES) or any(
                    read_private_bundle_item(fd, name, MAX_OUTPUT) != payload[name]
                    for name in FILES
                ):
                    raise Hold("PRIVATE comparison packet or original source changed")
            else:
                if os.listdir(fd):
                    raise Hold("PRIVATE comparison output folder must be empty")
                if source != read_sources(args):
                    raise Hold("original HUMAN source/selection changed during publication")
                publish_bundle(fd, list(payload.items()))
        finally:
            os.close(fd)
        print("PRIVATE_HUMAN_SELECTION_DIFF_" +
              ("REOPENED" if args.verify_output_dir else "CREATED") +
              " — REVIEW_ONLY; NO AUTHORITY")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HUMAN_SELECTION_DIFF_HOLD — sources or selections rejected", error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError):
        report_hold("PRIVATE_HUMAN_SELECTION_DIFF_HOLD — sources or selections rejected", None, args.explain_hold)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
