#!/usr/bin/env python3
"""Source-bound offline PRIVATE HUMAN role-return reconciliation.

Consolidates 1-5 exact original selected-role returns, publishes a private
ordinal-focused HUMAN change desk and counts-only artifacts. No authority.
"""
from __future__ import annotations

import argparse
import base64
import csv
from hashlib import sha256
from html import escape
import io
import json
import os
import sys

from launchpad import Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold
from review_desk import STAGES, ROLES, read_original_bundle
from history import admitted_rounds
from role_return_receipt import admit_return
from role_return_action_desk import NAME as ACTION_DESK, render as render_action_desk

FILES = (
    "lightup-lab-human-return-reconciliation-private.html",
    "lightup-lab-human-return-reconciliation-private.csv",
    "lightup-lab-human-unreturned-private.csv",
    "lightup-lab-human-role-worklist-private.csv",
    ACTION_DESK,
    "lightup-lab-human-return-reconciliation-counts.json",
    "START-HERE-RECONCILIATION-PRIVATE.txt",
)
LIMIT = 65536
STYLE = (
    "body{font:15px/1.55 system-ui,sans-serif;max-width:1050px;margin:2rem auto;"
    "padding:0 1rem;color:#132239;background:#f2f5fa}"
    ".hold{background:#fff3dd;border-left:6px solid #925012;padding:1rem;font-weight:bold}"
    "section{background:#fff;padding:1rem;border:1px solid #c7d5e4;border-radius:.6rem;margin:1rem 0}"
    "table{border-collapse:collapse;width:100%}th,td{padding:.65rem;text-align:left;"
    "border:1px solid #c5d2df}th{background:#e8f0fa}"
    "@media print{body{max-width:none}}"
)


def admitted_replies(paths, rounds, endpoints, digest):
    if not 1 <= len(paths) <= 5:
        raise Hold("reconciliation accepts between one and five PRIVATE role returns")
    seen_folders = set()
    seen_slots = set()
    replies = []
    for path in paths:
        folder, work, slots = admit_return(path, rounds, endpoints, digest)
        if folder in seen_folders:
            raise Hold("cannot reconcile the same PRIVATE role return twice")
        seen_folders.add(folder)
        if seen_slots.intersection(slots):
            raise Hold("two HUMAN returns claim the same original slot")
        seen_slots.update(slots)
        role = rounds[-1]["human_rows"][slots[0]]["role"]
        if role not in ROLES:
            raise Hold("invalid HUMAN role")
        if any(rounds[-1]["human_rows"][i]["role"] != role for i in slots):
            raise Hold("role return has inconsistent selected roles")
        replies.append((folder, role, slots, work))
    return replies


def render_files(replies, rounds, endpoints):
    before = rounds[-1]["human_rows"]
    # The private HTML and CSV carry role, original slot and HUMAN status only.
    # Never include endpoint URLs, original note text, source hashes or paths.
    records = []
    counts = []
    for _folder, role, slots, work in replies:
        changed_stage = 0
        changed_note = 0
        pending = 0
        for slot in slots:
            old = before[slot]
            new = work["human_rows"][slot]
            sc = old["stage"] != new["stage"]
            nc = old["note"] != new["note"]
            changed_stage += int(sc)
            changed_note += int(nc)
            pending += int(new["stage"] in ("NEEDS_INPUT", "FOLLOW_UP"))
            records.append((slot + 1, role, old["stage"], new["stage"],
                            "YES" if sc else "NO", "YES" if nc else "NO"))
        counts.append({
            "suggested_role": role, "returned_slot_count": len(slots),
            "changed_human_stage_count": changed_stage,
            "changed_private_note_count": changed_note,
            "pending_human_followup_count": pending,
        })
    records.sort(key=lambda entry: entry[0])
    selected = {row[0] for row in records}
    unreturned = [
        (index, row["role"], row["stage"])
        for index, row in enumerate(before, 1) if index not in selected
    ]
    # Even a HUMAN_REVIEW stage is not proof that anyone replied.
    missing_sink = io.StringIO(newline="")
    missing_csv = csv.writer(missing_sink, lineterminator="\n")
    missing_csv.writerow(("original_slot", "latest_suggested_role",
                          "last_self_reported_human_stage"))
    missing_csv.writerows(unreturned)
    current = {record[0]: record for record in records}
    actions = {
        "NEEDS_INPUT": "COLLECT_MISSING_HUMAN_INPUT",
        "HUMAN_REVIEW": "SCHEDULE_HUMAN_REVIEW",
        "FOLLOW_UP": "FOLLOW_UP_WITH_HUMAN_OWNER",
    }
    work = []
    for ordinal, prior in enumerate(before, 1):
        returned = current.get(ordinal)
        stage = returned[3] if returned else prior["stage"]
        status = "ROLE_REPLY_RECEIVED" if returned else "AWAITING_HUMAN_ROLE_REPLY"
        work.append((ordinal, prior["role"], status, stage,
                     actions[stage] if returned else "REQUEST_HUMAN_ROLE_REPLY",
                     returned[5] if returned else "NOT_RETURNED"))
    work.sort(key=lambda row: (0 if row[2] == "AWAITING_HUMAN_ROLE_REPLY" else 1,
                               0 if row[3] == "NEEDS_INPUT" else 1,
                               row[0]))
    work_sink = io.StringIO(newline="")
    work_csv = csv.writer(work_sink, lineterminator="\n")
    work_csv.writerow(("original_slot", "latest_suggested_role",
                       "private_human_reply_status", "latest_self_reported_human_stage",
                       "suggested_operator_next_step", "private_note_changed"))
    work_csv.writerows(work)
    work_rows = "".join(
        "<tr>" + "".join("<td>" + escape(str(cell)) + "</td>" for cell in row)
        + "</tr>" for row in work
    )
    missing_html = "".join(
        "<tr>" + "".join("<td>" + escape(str(cell)) + "</td>" for cell in row)
        + "</tr>" for row in unreturned
    )
    sink = io.StringIO(newline="")
    writer = csv.writer(sink, lineterminator="\n")
    writer.writerow(("original_slot", "suggested_human_role", "prior_human_stage",
                     "proposed_human_stage", "human_stage_changed",
                     "private_note_changed"))
    writer.writerows(records)
    table = "".join(
        "<tr>" + "".join("<td>" + escape(str(cell)) + "</td>"
                         for cell in row) + "</tr>" for row in records
    )
    summary = {
        "schema": "lightup.assessment_launchpad_private_role_reconciliation_counts.v1",
        "status": "REVIEW_ONLY",
        "original_lab_endpoint_count": len(endpoints),
        "operator_ordered_round_count": len(rounds),
        "return_packet_count": len(replies),
        "selected_original_slot_count": len(records),
        "nonselected_original_slot_count": len(unreturned),
        "nonreturned_last_self_reported_stages": {
            key: sum(item[2] == key for item in unreturned) for key in STAGES
        },
        "nonreturned_last_suggested_roles": {
            key: sum(item[1] == key for item in unreturned) for key in ROLES
        },
        "changed_human_stage_count": sum(row[4] == "YES" for row in records),
        "changed_private_note_count": sum(row[5] == "YES" for row in records),
        "next_human_actions": {
            action: sum(row[4] == action for row in work)
            for action in ("REQUEST_HUMAN_ROLE_REPLY", *actions.values())
        },
        "role_packets": counts,
        "authentication_verified": False,
        "authorization_granted": False,
        "human_go": False,
    }
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        + "style-src 'sha256-" + style_hash + "'; script-src 'none'; "
        "connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN role reconciliation</title><style>" +
        STYLE + "</style></head><body><h1>PRIVATE HUMAN role reconciliation</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY ·"
        " NO AUTHORIZATION</p><section><p>" + str(len(replies)) +
        " voluntarily suggested role-return packets; " + str(len(records)) +
        " selected local lab slots of " + str(len(endpoints)) + " originals."
        " All HUMAN ordering is operator-selected, not authenticated time.</p>"
        "<p>Original endpoint URLs, note text, hashes, filesystem paths, client "
        "records and recipient identities are deliberately NOT included. Slot "
        "ordinals and role combinations may still be personally identifiable."
        " Do not publish or forward this PRIVATE record.</p></section>"
        "<section><h2>Selected HUMAN review changes</h2><table><thead>"
        "<tr><th>Original slot</th><th>Suggested role</th><th>Prior HUMAN stage</th>"
        "<th>Proposed HUMAN stage</th><th>Stage changed</th><th>Note changed</th>"
        "</tr></thead><tbody>" + table + "</tbody></table></section>"
        "<section><h2>HUMAN slots WITHOUT a returned role packet</h2>"
        "<p>" + str(len(unreturned)) + " original source slots have NO locally "
        "admitted selected-role return in this collection. A prior HUMAN_REVIEW "
        "stage does not mean a reviewer responded. Suggested roles are unverified "
        "and never authorize an assessment.</p>"
        "<table><thead><tr><th>Original slot</th><th>Last suggested HUMAN role</th>"
        "<th>Last self-reported HUMAN stage</th></tr></thead><tbody>" +
        missing_html + "</tbody></table></section>"
        "<section><h2>PRIVATE next HUMAN actions</h2>"
        "<p>Owner-only suggested actions based on original HUMAN self-report."
        " Missing recipient answers remain visible even if previous stage"
        " was HUMAN_REVIEW. No endpoint URL or PRIVATE note text included.</p>"
        "<table><thead><tr><th>Original slot</th><th>Suggested role</th>"
        "<th>Role reply</th><th>HUMAN stage</th><th>Suggested HUMAN next step</th>"
        "<th>Note changed?</th></tr></thead><tbody>" + work_rows +
        "</tbody></table></section>"
        "<p>Only exact source-bound local HUMAN self-reports were combined; "
        "this is not recipient authentication, remediation proof, scope approval, "
        "client or operator consent, action-time revocation, a scan permit "
        "or HUMAN GO. No network, target or model execution.</p>"
        "</body></html>"
    ).encode("utf-8")
    guide = (
        "LIGHTUP PRIVATE HUMAN ROLE RETURN RECONCILIATION\n"
        "PLAN/LAB ONLY · REVIEW_ONLY · DRAFT/HOLD · NO AUTHORIZATION\n"
        "This is an UNSIGNED local source-bound HUMAN self-report summary.\n"
        "Every source packet was re-admitted against the exact original source.\n"
        "Both original-ordinal CSV files omit endpoint URLs and private note text.\n"
        "The UNRETURNED CSV lists local original slots not selected by any return.\n"        "The PRIVATE HUMAN worklist CSV proposes only fixed, non-authorizing\n"
        "human follow-up actions based on original untrusted review stages.\n"
        "An older HUMAN stage, including HUMAN_REVIEW, never proves response.\n"
        "Small cohorts, roles and ordinal combinations may remain identifying.\n"
        "Counts-only JSON provides no real proof of review, consent or safety.\n"
        "Use the original private role returns with advance.py --role-return-dir\n"
        "to create the actual next HUMAN round; this report does not create one.\n"
        "Never host, email publicly or use this packet as a grant/scan permit.\n"
    ).encode("utf-8")
    json_bytes = (json.dumps(summary, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")) + "\n").encode("utf-8")
    return dict(zip(FILES, (
        html, sink.getvalue().encode("utf-8"),
        missing_sink.getvalue().encode("utf-8"),
        work_sink.getvalue().encode("utf-8"),
        render_action_desk(work), json_bytes, guide)))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline original-source HUMAN role reconciliation")
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--round-dir", action="append", required=True,
                        help="2-8 original HUMAN rounds, ordered exactly as the returns")
    parser.add_argument("--role-return-dir", action="append", required=True,
                        help="1-5 complete PRIVATE two-file role returns")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output-dir", help="fresh existing empty mode-0700 destination")
    mode.add_argument("--verify-output-dir", help="read-only exact source-bound reopen")
    parser.add_argument("--explain-hold", action="store_true", help="print curated HOLD reason; raw paths, endpoint values and exceptions stay hidden")
    args = parser.parse_args(argv)
    try:
        original, endpoints, digest = read_original_bundle(args.bundle_dir)
        source_dirs, rounds = admitted_rounds(args.round_dir, digest, endpoints)
        replies = admitted_replies(args.role_return_dir, rounds, endpoints, digest)
        expected = render_files(replies, rounds, endpoints)
        if any(not 0 < len(blob) <= LIMIT for blob in expected.values()):
            raise Hold("bounded PRIVATE role reconciliation capacity exceeded")
        fd, dest = open_output_directory(args.output_dir or args.verify_output_dir)
        try:
            sources = (original, *source_dirs, *(row[0] for row in replies))
            if any(os.path.commonpath((source, dest)) in (source, dest)
                   for source in sources):
                raise Hold("reconciliation destination overlaps PRIVATE source")
            if args.verify_output_dir:
                if set(os.listdir(fd)) != set(FILES) or any(
                        read_private_bundle_item(fd, name, LIMIT) != expected[name]
                        for name in FILES):
                    raise Hold("PRIVATE reconciliation output differs from exact source")
            else:
                if os.listdir(fd):
                    raise Hold("reconciliation destination must be empty")
                newer_original, newer_endpoints, newer_digest = read_original_bundle(args.bundle_dir)
                newer_dirs, newer_rounds = admitted_rounds(
                    args.round_dir, newer_digest, newer_endpoints)
                newer_replies = admitted_replies(
                    args.role_return_dir, newer_rounds, newer_endpoints, newer_digest)
                if ((original, endpoints, digest, source_dirs, rounds, replies)
                        != (newer_original, newer_endpoints, newer_digest,
                            newer_dirs, newer_rounds, newer_replies)):
                    raise Hold("original source or private HUMAN role returns changed")
                publish_bundle(fd, list(expected.items()))
        finally:
            os.close(fd)
        print("PRIVATE_HUMAN_ROLE_RECONCILIATION_" +
              ("REOPENED" if args.verify_output_dir else "CREATED") +
              " — UNSIGNED HUMAN REVIEW_ONLY; NO AUTHORITY")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HUMAN_RECONCILIATION_HOLD — original source/return not admitted", error, args.explain_hold)
        return 3
    except (OSError, ValueError, UnicodeError, TypeError, OverflowError, csv.Error):
        report_hold("PRIVATE_HUMAN_RECONCILIATION_HOLD — original source/return not admitted", None, args.explain_hold)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
