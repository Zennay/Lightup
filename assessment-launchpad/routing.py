#!/usr/bin/env python3
"""Offline source-bound role-specific HUMAN follow-up inbox for LightUp Launchpad.

Never performs an assessment, network call, client authorization or HUMAN GO.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
from html import escape
import json
import os
import sys

from launchpad import FLAGS, Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold
from review_desk import ROLES, STAGES, read_original_bundle
from compare_review import read_round

FILES = (
    "lightup-lab-human-routing-private.html",
    "lightup-lab-human-routing-private.csv",
    "lightup-lab-human-routing-counts.json",
)
STYLE = ("body{font:15px/1.55 system-ui,sans-serif;color:#17212f;"
         "max-width:1100px;margin:2rem auto;padding:0 1rem}"
         "h1{font-size:1.9rem}.hold{border:2px solid #9a5b18;"
         "background:#fff6e7;padding:1rem;font-weight:750}"
         "table{border-collapse:collapse;width:100%}"
         "th,td{border:1px solid #b8c4d3;padding:.7rem;text-align:left;vertical-align:top}"
         "th{background:#f1f5fa}pre{white-space:pre-wrap;overflow-wrap:anywhere}"
         "code{overflow-wrap:anywhere}small{color:#475569}"
         "@media print{body{margin:0;max-width:none}}")

def select(work, role, stage):
    return [row for row in work["human_rows"]
            if (role == "ALL" or row["role"] == role)
            and (stage == "ALL" or row["stage"] == stage)]

def create_artifacts(work, endpoints, role, stage):
    rows = select(work, role, stage)
    rows = sorted(rows, key=lambda r: (ROLES.index(r["role"]), STAGES.index(r["stage"]), r["slot"]))
    summary = {
        "schema": "lightup.assessment_launchpad_human_routing_counts.v1",
        "status": "REVIEW_ONLY",
        "source_reported_endpoint_count": len(endpoints),
        "filtered_human_rows": len(rows),
        "selected_role": role,
        "selected_stage": stage,
        "role_counts": {item: sum(row["role"] == item for row in rows) for item in ROLES},
        "stage_counts": {item: sum(row["stage"] == item for row in rows) for item in STAGES},
        "source_identifiers_embedded": False,
        "original_source_digest_embedded": False,
        "private_notes_embedded": False,
        "source_paths_embedded": False,
        "counts_are_not_authority": True,
        **{key: False for key in FLAGS},
    }
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    lines = []
    for row in rows:
        endpoint = endpoints[row["slot"] - 1]
        lines.append("<tr><td>" + str(row["slot"]) + "</td><td><code>" +
                     escape(endpoint) + "</code></td><td>" + escape(row["stage"]) +
                     "</td><td>" + escape(row["role"]) + "</td><td><pre>" +
                     escape(row["note"]) + "</pre></td></tr>")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " style-src 'sha256-" + style_hash +
        "'; script-src 'none'; connect-src 'none'; img-src 'none';"
        " object-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE HUMAN routing inbox</title><style>" + STYLE +
        "</style></head><body><h1>Private human follow-up inbox</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "
        "REVIEW_ONLY · NOT AUTHORIZED</p><p>Human-selected role: <strong>" +
        escape(role) + "</strong>; HUMAN stage: <strong>" + escape(stage) +
        "</strong>. Displaying " + str(len(rows)) + " of " +
        str(len(endpoints)) + " source-bound planning slots.</p>"
        "<p>This is a PRIVATE role-filtered LOCAL operator dossier. "
        "It includes endpoint URLs and HUMAN notes; do not host, share or "
        "treat it as client consent, review approval, completed remediation, "
        "a finding, a permission to scan or HUMAN GO.</p>"
        "<table><thead><tr><th>Original slot</th><th>PRIVATE local endpoint</th>"
        "<th>HUMAN stage</th><th>Suggested role</th><th>Private operator note</th>"
        "</tr></thead><tbody>" + "".join(lines) + "</tbody></table>"
        "<p><small>Actual source authority, time-valid scope, consent, "
        "revocation and independent reviews must be checked separately. "
        "The offline Launchpad has not contacted targets or run a model."
        "</small></p></body></html>"
    ).encode("utf-8")
    # Fixed admitted vocabulary and integer ordinals only; no original values,
    # notes or formulas enter the CSV. Per-slot rows are PRIVATE, not anonymous.
    csv_lines = ["original_slot,human_stage,suggested_role,private_note_length"]
    csv_lines.extend(str(row["slot"]) + "," + row["stage"] + "," + row["role"] +
                     "," + str(len(row["note"])) for row in rows)
    return [
        (FILES[0], html),
        (FILES[1], ("\n".join(csv_lines) + "\n").encode("utf-8")),
        (FILES[2], (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8")),
    ]

def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Produce/reopen PRIVATE HUMAN role-specific follow-up, without any target work."))
    parser.add_argument("--bundle-dir", required=True, help="original five-file Launchpad packet")
    parser.add_argument("--round-dir", required=True, help="one source-bound PRIVATE HUMAN round")
    parser.add_argument("--role", choices=("ALL", *ROLES), default="ALL")
    parser.add_argument("--stage", choices=("ALL", *STAGES), default="ALL")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output-dir", help="NEW separate mode-0700 directory")
    destination.add_argument("--verify-routing-dir", help="read-only reopen a completed routing desk")
    parser.add_argument("--explain-hold", action="store_true",
                        help="print the curated non-sensitive HOLD reason; never prints paths, endpoint values or raw exceptions")
    args = parser.parse_args(argv)
    try:
        original_dir, endpoints, digest = read_original_bundle(args.bundle_dir)
        round_dir, worksheet = read_round(args.round_dir, digest, endpoints)
        output_fd, output_dir = open_output_directory(args.output_dir or args.verify_routing_dir)
        try:
            for existing in (original_dir, round_dir):
                if os.path.commonpath((existing, output_dir)) in (existing, output_dir):
                    raise Hold("PRIVATE routing output must be separate from all sources")
            expected = dict(create_artifacts(worksheet, endpoints, args.role, args.stage))
            if args.verify_routing_dir:
                if set(os.listdir(output_fd)) != set(FILES):
                    raise Hold("PRIVATE HUMAN routing directory has missing or unexpected files")
                received = {name: read_private_bundle_item(output_fd, name, 65536)
                            for name in FILES}
                if received != expected:
                    raise Hold("routing handoff changed or no longer matches exact source")
            else:
                if os.listdir(output_fd):
                    raise Hold("new PRIVATE HUMAN routing directory must be empty")
                renewed_dir, renewed_endpoints, renewed_digest = read_original_bundle(args.bundle_dir)
                renewed_round_dir, renewed_worksheet = read_round(
                    args.round_dir, renewed_digest, renewed_endpoints)
                if ((renewed_dir, renewed_endpoints, renewed_digest) !=
                        (original_dir, endpoints, digest)
                        or (renewed_round_dir, renewed_worksheet) != (round_dir, worksheet)):
                    raise Hold("source or HUMAN round drifted before private routing publication")
                publish_bundle(output_fd, list(expected.items()))
        finally:
            os.close(output_fd)
        print("PRIVATE_HUMAN_ROUTING_" +
              ("REOPENED" if args.verify_routing_dir else "CREATED") +
              " role=" + args.role + " stage=" + args.stage +
              " — HUMAN PLANNING ONLY; UNSIGNED; NO AUTHORIZATION OR EXECUTION")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HUMAN_ROUTING_HOLD — source-bound inputs not admitted",
                    error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, UnicodeError, ImportError, OverflowError):
        report_hold("PRIVATE_HUMAN_ROUTING_HOLD — source-bound inputs not admitted",
                    None, args.explain_hold)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
