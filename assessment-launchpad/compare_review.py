#!/usr/bin/env python3
"""Offline source-bound comparison of two private HUMAN-only Launchpad review rounds."""
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
from review_desk import (
    FILE_NAMES, STAGES, ROLES, load_json, read_original_bundle,
    validate_worksheet, make_artifacts,
)

NAMES = (
    "lightup-lab-human-delta-private.html",
    "lightup-lab-human-delta-counts.json",
    "lightup-lab-human-delta-counts.csv",
)
STYLE = ("body{font:15px/1.5 system-ui,sans-serif;color:#17212f;max-width:1000px;"
         "margin:2rem auto;padding:0 1rem}h1{font-size:1.8rem}.hold{border:2px solid #9a5b18;"
         "padding:1rem;background:#fff7ed;font-weight:bold}table{border-collapse:collapse;"
         "width:100%}th,td{padding:.7rem;border:1px solid #cad4df;text-align:left}"
         "th{background:#eff3f8}small{color:#475569}@media print{body{margin:0;max-width:none}}")

def read_round(path, digest, endpoints):
    directory_fd, absolute = open_output_directory(path)
    try:
        if set(os.listdir(directory_fd)) != set(FILE_NAMES):
            raise Hold("PRIVATE HUMAN round has missing or unexpected artifacts")
        received = {name: read_private_bundle_item(directory_fd, name, 65536)
                    for name in FILE_NAMES}
    finally:
        os.close(directory_fd)
    work = load_json(received[FILE_NAMES[0]])
    validate_worksheet(work, digest, len(endpoints))
    expected = dict(make_artifacts(work, endpoints))
    if received != expected:
        raise Hold("HUMAN round files are incomplete, modified, or no longer source-bound")
    return absolute, work

def build_delta(first, second):
    before = first["human_rows"]
    after = second["human_rows"]
    changes = []
    for old, new in zip(before, after):
        stage_changed = old["stage"] != new["stage"]
        role_changed = old["role"] != new["role"]
        note_changed = old["note"] != new["note"]
        if stage_changed or role_changed or note_changed:
            changes.append({
                "slot": old["slot"],
                "previous_stage": old["stage"], "current_stage": new["stage"],
                "previous_role": old["role"], "current_role": new["role"],
                "note_changed": note_changed,
            })
    summary = {
        "schema": "lightup.assessment_launchpad_human_delta_counts.v1",
        "status": "REVIEW_ONLY",
        "ordering": "operator_selected_not_authenticated_chronology",
        "source_reported_endpoint_count": len(before),
        "changed_human_slots": len(changes),
        "changed_stages": sum(a["stage"] != b["stage"] for a, b in zip(before, after)),
        "changed_roles": sum(a["role"] != b["role"] for a, b in zip(before, after)),
        "changed_private_notes": sum(a["note"] != b["note"] for a, b in zip(before, after)),
        "previous_stage_counts": {s: sum(row["stage"] == s for row in before) for s in STAGES},
        "current_stage_counts": {s: sum(row["stage"] == s for row in after) for s in STAGES},
        "previous_role_counts": {s: sum(row["role"] == s for row in before) for s in ROLES},
        "current_role_counts": {s: sum(row["role"] == s for row in after) for s in ROLES},
        "endpoint_values_embedded": False,
        "original_source_digest_embedded": False,
        "source_paths_embedded": False,
        "private_notes_embedded": False,
        "revised_human_state_not_authority": True,
        **{key: False for key in FLAGS},
    }
    return changes, summary

def make_artifacts(first, second):
    changes, summary = build_delta(first, second)
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    table_rows = []
    for row in changes:
        table_rows.append(
            "<tr><td>" + str(row["slot"]) + "</td><td>" +
            escape(row["previous_stage"]) + " → " + escape(row["current_stage"]) +
            "</td><td>" + escape(row["previous_role"]) + " → " +
            escape(row["current_role"]) + "</td><td>" +
            ("YES" if row["note_changed"] else "NO") + "</td></tr>"
        )
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " style-src 'sha256-" + style_hash + "'; script-src 'none'; connect-src 'none';"
        " img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp HUMAN review round delta</title><style>" + STYLE +
        "</style></head><body><h1>Manual HUMAN follow-up changes</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "
        "REVIEW_ONLY · NO AUTHORITY</p>"
        "<p>Changes between TWO manually ordered, original-source-bound private "
        "review rounds. Their selected order is not authenticated chronology."
        " Changed or missing notes/stages do not mean a tested endpoint is fixed, "
        "revoked, cleared or authorized.</p><p>" +
        str(summary["changed_human_slots"]) + " of " +
        str(summary["source_reported_endpoint_count"]) + " HUMAN slots differ.</p>"
        "<table><thead><tr><th>Original ordinal</th><th>HUMAN stage</th>"
        "<th>Neutral reviewer role</th><th>Private note modified?</th>"
        "</tr></thead><tbody>" + "".join(table_rows) + "</tbody></table>"
        "<p><small>No endpoint URLs, source hashes, private notes, client identities "
        "or source paths are embedded here. These are unsigned local consistency "
        "counts, not authorization, findings, an assessed result or HUMAN GO. "
        "No network or assessment action occurred.</small></p></body></html>"
    ).encode("utf-8")
    rows = ["category,value,count",
            "changed_human_slots,all," + str(summary["changed_human_slots"]),
            "changed_stages,all," + str(summary["changed_stages"]),
            "changed_roles,all," + str(summary["changed_roles"]),
            "changed_private_notes,all," + str(summary["changed_private_notes"]),
            "source_reported_endpoint_count,all," +
            str(summary["source_reported_endpoint_count"])]
    for key in ("previous_stage_counts", "current_stage_counts",
                "previous_role_counts", "current_role_counts"):
        rows.extend(key + "," + value + "," + str(number)
                    for value, number in summary[key].items())
    return [
        (NAMES[0], html),
        (NAMES[1], (json.dumps(summary, indent=2, ensure_ascii=False) + "\n").encode("utf-8")),
        (NAMES[2], ("\n".join(rows) + "\n").encode("utf-8")),
    ]

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare two HUMAN follow-up rounds offline without running assessments.")
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--before-dir", required=True)
    parser.add_argument("--after-dir", required=True)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--output-dir")
    output.add_argument("--verify-delta-dir")
    parser.add_argument("--explain-hold", action="store_true", help="print curated HOLD reason; raw paths, endpoint values and exceptions stay hidden")
    args = parser.parse_args(argv)
    try:
        original, endpoints, digest = read_original_bundle(args.bundle_dir)
        first_dir, first = read_round(args.before_dir, digest, endpoints)
        second_dir, second = read_round(args.after_dir, digest, endpoints)
        if first_dir == second_dir:
            raise Hold("two distinct source-bound HUMAN rounds are required")
        fd, dest = open_output_directory(args.output_dir or args.verify_delta_dir)
        try:
            for source in (original, first_dir, second_dir):
                if os.path.commonpath((source, dest)) in (source, dest):
                    raise Hold("delta output must be separate from all source directories")
            desired = dict(make_artifacts(first, second))
            if args.verify_delta_dir:
                if set(os.listdir(fd)) != set(NAMES):
                    raise Hold("PRIVATE HUMAN comparison contains unknown or missing files")
                actual = {name: read_private_bundle_item(fd, name, 65536)
                          for name in NAMES}
                if actual != desired:
                    raise Hold("stored HUMAN delta changed or no longer matches exact rounds")
            else:
                if os.listdir(fd):
                    raise Hold("new PRIVATE HUMAN comparison directory must be empty")
                # In a long-running operator handoff, source rounds may change
                # between initial admission and output publication.
                fresh_original, fresh_endpoints, fresh_digest = read_original_bundle(args.bundle_dir)
                fresh_before_dir, fresh_before = read_round(args.before_dir, fresh_digest, fresh_endpoints)
                fresh_after_dir, fresh_after = read_round(args.after_dir, fresh_digest, fresh_endpoints)
                if ((fresh_original, fresh_endpoints, fresh_digest) != (original, endpoints, digest)
                        or (fresh_before_dir, fresh_before) != (first_dir, first)
                        or (fresh_after_dir, fresh_after) != (second_dir, second)):
                    raise Hold("original source or HUMAN round changed before output")
                publish_bundle(fd, list(desired.items()))
        finally:
            os.close(fd)
        print("HUMAN_DELTA_" + ("REOPENED" if args.verify_delta_dir else "CREATED") +
              " — REVIEW_ONLY, UNSIGNED; NO TARGET ACTION OR AUTHORIZATION")
        return 0
    except Hold as error:
        report_hold("HUMAN_DELTA_HOLD — original source or HUMAN rounds not admitted", error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, UnicodeError, ImportError, OverflowError):
        report_hold("HUMAN_DELTA_HOLD — original source or HUMAN rounds not admitted", None, args.explain_hold)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
