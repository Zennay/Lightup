#!/usr/bin/env python3
"""Private, voluntarily role-filtered HUMAN handoff from existing lab-only rounds.

Role strings are untrusted HUMAN self-reports, never authentication or scope
authority. No network, target I/O, model, authorization, or command execution.
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
from history import admitted_rounds

NAMES = (
    "lightup-lab-role-handoff-private.html",
    "lightup-lab-role-handoff-private.csv",
    "lightup-lab-role-handoff-counts.json",
    "START-HERE-ROLE-PRIVATE.txt",
)
LIMIT = 524_288
STYLE = (
    "body{font:15px/1.55 system-ui,sans-serif;background:#f6f8fb;color:#142336;"
    "max-width:1080px;margin:2rem auto;padding:0 1rem}"
    "h1{font-size:2rem}.hold{background:#fff3df;border-left:6px solid #985318;"
    "padding:1rem;font-weight:750}section{background:#fff;border:1px solid #d2dce8;"
    "padding:1rem;border-radius:.55rem;margin:1rem 0}table{width:100%;"
    "border-collapse:collapse}th,td{border:1px solid #bdcbd9;padding:.65rem;"
    "vertical-align:top;text-align:left}th{background:#edf3fa}"
    "pre{white-space:pre-wrap;overflow-wrap:anywhere}"
    "code{overflow-wrap:anywhere}small{color:#4e5b6a}"
    "@media print{body{margin:0;max-width:none}}"
)

def select(rounds, role, stage, selected_slots=None):
    """Only select latest HUMAN role; old notes appear only under the SAME role."""
    latest = rounds[-1]["human_rows"]
    matches = [row["slot"] - 1 for row in latest
               if row["role"] == role and (stage == "ALL" or row["stage"] == stage)]
    if selected_slots is None or not selected_slots:
        return matches
    if (len(selected_slots) > len(latest)
            or any(type(slot) is not int or not 1 <= slot <= len(latest)
                   for slot in selected_slots)
            or len(set(selected_slots)) != len(selected_slots)):
        raise Hold("HUMAN slot filter requires unique existing original ordinals")
    selected = {slot - 1 for slot in selected_slots}
    if not selected.issubset(matches):
        raise Hold("requested HUMAN slot is not assigned to this latest role/stage")
    return [index for index in matches if index in selected]

def assemble(rounds, endpoints, role, stage, selected_slots=None):
    indices = select(rounds, role, stage, selected_slots)
    # A role-specific handoff must not be described as evidence when nothing
    # matches; require an intentional nonempty HUMAN selection.
    if not indices:
        raise Hold("no HUMAN slots match the selected voluntary role/stage")
    count_rows = []
    sections = []
    csv_rows = ["original_slot,current_human_stage,current_suggested_role,"
                "human_rounds_with_matching_role,private_note_characters_latest"]
    all_rounds = len(rounds)
    for index in indices:
        current = rounds[-1]["human_rows"][index]
        visible = []
        matching = 0
        for number, work in enumerate(rounds, 1):
            row = work["human_rows"][index]
            if row["role"] != role:
                # Cross-role HUMAN notes and all prior self-report fields stay
                # withheld from the voluntarily selected private role packet.
                visible.append(
                    "<tr><td>" + str(number) + "</td><td colspan='3'>"
                    "NOT INCLUDED: this HUMAN round had another suggested role."
                    "</td></tr>"
                )
            else:
                matching += 1
                visible.append(
                    "<tr><td>" + str(number) + "</td><td>" +
                    escape(row["stage"]) + "</td><td>" + escape(row["role"]) +
                    "</td><td><pre>" + escape(row["note"]) + "</pre></td></tr>"
                )
        sections.append(
            "<section><h2>Original local lab slot " + str(index + 1).zfill(2) +
            "</h2><p>PRIVATE original endpoint URL: <code>" +
            escape(endpoints[index]) + "</code></p><p>Current HUMAN stage: " +
            escape(current["stage"]) + "; suggested reviewer role: " +
            escape(current["role"]) + ".</p>"
            "<table><thead><tr><th>Manual round</th><th>Self-reported stage</th>"
            "<th>Suggested role</th><th>PRIVATE note</th></tr></thead><tbody>" +
            "".join(visible) + "</tbody></table></section>"
        )
        csv_rows.append(
            str(index + 1) + "," + current["stage"] + "," + current["role"] +
            "," + str(matching) + "," + str(len(current["note"]))
        )
        count_rows.append({
            "matching_human_rounds": matching,
            "current_stage": current["stage"],
        })
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " style-src 'sha256-" + style_hash +
        "'; script-src 'none'; connect-src 'none'; img-src 'none'; "
        "object-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE role-filtered HUMAN dossier</title>"
        "<style>" + STYLE + "</style></head><body>"
        "<h1>PRIVATE HUMAN follow-up dossier</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "
        "REVIEW_ONLY · NO AUTHORIZATION</p>"
        "<p>Voluntarily selected HUMAN role: <strong>" + escape(role) +
        "</strong>; latest HUMAN stage filter: <strong>" + escape(stage) +
        "</strong>; selected local lab slots: " + str(len(indices)) +
        " of " + str(len(endpoints)) + "; manually ordered HUMAN rounds: " +
        str(all_rounds) + ".</p>"
        "<p>PRIVATE offline packet for local operator preparation only. "
        "Selected endpoint URLs and notes are confidential. Notes from rounds "
        "assigned to a different suggested role are deliberately omitted. "
        "This filter is NOT identity verification, an access-control boundary, "
        "client approval, scope permission, evidence of completed review or HUMAN GO."
        "</p>" + "".join(sections) +
        "<p><small>Original source and HUMAN packets were locally re-admitted "
        "without target I/O. Round order is manually provided, not authenticated "
        "chronology. An omitted other-role note may still exist in the unchanged "
        "source packet. Never host, email publicly, or use as a scan permit."
        "</small></p></body></html>"
    ).encode("utf-8")
    counts = {
        "schema": "lightup.assessment_launchpad_role_handoff_counts.v1",
        "status": "REVIEW_ONLY",
        "source_reported_endpoint_count": len(endpoints),
        "human_round_count": all_rounds,
        "selected_human_role": role,
        "selected_latest_stage": stage,
        "selected_human_slots": len(indices),
        "explicit_ordinal_subset_used": bool(selected_slots),
        "selected_current_human_stage_counts": {
            label: sum(value["current_stage"] == label for value in count_rows)
            for label in STAGES
        },
        "matching_role_rounds_counts": {
            str(number): sum(value["matching_human_rounds"] == number for value in count_rows)
            for number in range(1, all_rounds + 1)
        },
        "source_values_embedded": False,
        "per_slot_identifiers_embedded": False,
        "private_note_text_embedded": False,
        "source_digest_embedded": False,
        "source_paths_embedded": False,
        "role_filter_is_not_authentication": True,
        "manual_order_is_not_authenticated_time": True,
        **{key: False for key in FLAGS},
    }
    guide = (
        "LightUp PRIVATE manually role-filtered HUMAN handoff\n"
        "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NOT AUTHORIZED\n"
        "Role filter: " + role + "; latest HUMAN stage filter: " + stage + "\n"
        "Selected original HUMAN slots: " + str(len(indices)) + "\n"
        "Explicit original-slot minimization applied: " +
        ("YES" if selected_slots else "NO") + "\n"
        "Manually ordered HUMAN rounds: " + str(all_rounds) + "\n"
        "The HTML contains PRIVATE original local endpoint URLs and HUMAN notes.\n"
        "Only notes from HUMAN rounds with the same suggested role are shown.\n"
        "The CSV contains original slot ordinals and selected fixed HUMAN fields.\n"
        "The JSON contains counts ONLY, but small engagement counts can be identifying.\n"
        "The role and stages are editable unsigned self-reports, not real ownership,\n"
        "authentication, consent, scope approval, risk clearance or HUMAN GO.\n"
        "Never publish or host this packet. To reopen, supply all unchanged original\n"
        "private source and HUMAN rounds and use role_handoff.py --verify-handoff-dir.\n"
        "Original independent security/privacy review, exact-head permanent VPS CI,\n"
        "true separate client/operator consent and action-time revocation remain required.\n"
    ).encode("utf-8")
    return [
        (NAMES[0], html),
        (NAMES[1], ("\n".join(csv_rows) + "\n").encode("utf-8")),
        (NAMES[2], (json.dumps(counts, ensure_ascii=False, indent=2) + "\n").encode("utf-8")),
        (NAMES[3], guide),
    ]

def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Offline voluntary HUMAN role-filtered PRIVATE handoff, never a permission grant."))
    parser.add_argument("--bundle-dir", required=True, help="original five-file private source packet")
    parser.add_argument("--round-dir", action="append", required=True,
                        help="2–8 complete private HUMAN rounds, in manually selected order")
    parser.add_argument("--role", choices=ROLES, required=True,
                        help="fixed HUMAN role value, NOT an identity or access check")
    parser.add_argument("--stage", choices=("ALL", *STAGES), default="ALL",
                        help="optional latest HUMAN self-report stage filter")
    parser.add_argument("--slot", type=int, action="append",
                        help="optional PRIVATE original slot ordinal, repeat for the minimal needed subset")
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--output-dir", help="NEW separate owner-only empty mode-0700 directory")
    output.add_argument("--verify-handoff-dir", help="read-only reopen a prior PRIVATE handoff")
    parser.add_argument("--explain-hold", action="store_true", help="print curated HOLD reason; raw paths, endpoint values and exceptions stay hidden")
    args = parser.parse_args(argv)
    try:
        original, endpoints, digest = read_original_bundle(args.bundle_dir)
        round_dirs, rounds = admitted_rounds(args.round_dir, digest, endpoints)
        fd, dest = open_output_directory(args.output_dir or args.verify_handoff_dir)
        try:
            for source in (original, *round_dirs):
                if os.path.commonpath((source, dest)) in (source, dest):
                    raise Hold("role handoff must be separate from original PRIVATE source and HUMAN rounds")
            expected = dict(assemble(rounds, endpoints, args.role, args.stage, args.slot))
            if any(not 0 < len(data) <= LIMIT for data in expected.values()):
                raise Hold("PRIVATE role handoff exceeds bounded output capacity")
            if args.verify_handoff_dir:
                if set(os.listdir(fd)) != set(NAMES):
                    raise Hold("PRIVATE role handoff has unexpected or missing files")
                actual = {name: read_private_bundle_item(fd, name, LIMIT)
                          for name in NAMES}
                if actual != expected:
                    raise Hold("PRIVATE role handoff no longer matches source-bound HUMAN inputs")
            else:
                if os.listdir(fd):
                    raise Hold("PRIVATE role handoff output must start empty")
                renewed, current_endpoints, current_digest = read_original_bundle(args.bundle_dir)
                new_dirs, new_rounds = admitted_rounds(
                    args.round_dir, current_digest, current_endpoints)
                if (renewed, current_endpoints, current_digest, new_dirs, new_rounds) != (
                        original, endpoints, digest, round_dirs, rounds):
                    raise Hold("original source or HUMAN rounds changed before role handoff publication")
                publish_bundle(fd, list(expected.items()))
        finally:
            os.close(fd)
        print("PRIVATE_HUMAN_ROLE_HANDOFF_" +
              ("REOPENED" if args.verify_handoff_dir else "CREATED") +
              " role=" + args.role + " stage=" + args.stage +
              " — VOLUNTARY FILTER ONLY; UNSIGNED; NO AUTHORITY OR TARGET ACTIVITY")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HUMAN_ROLE_HANDOFF_HOLD — original source or selected HUMAN round not admitted", error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, UnicodeError, ImportError, OverflowError):
        report_hold("PRIVATE_HUMAN_ROLE_HANDOFF_HOLD — original source or selected HUMAN round not admitted", None, args.explain_hold)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
