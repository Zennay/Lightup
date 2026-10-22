"""Owner-only native intake of resolved source-bound HUMAN overlap choices.

Not a security permission: exact offline original-source & human-choice custody.
"""
from __future__ import annotations

import base64
import csv
from hashlib import sha256
from html import escape
import io
import os

from launchpad import Hold, open_output_directory, read_private_bundle_item
from review_desk import load_json, require_private_file, validate_worksheet
from role_return_conflicts import (RESOLVED, LIMIT, read_packets,
                                   source_set_digest, resolve_files)
from role_return_action_desk import NAME as ACTION_HTML, render as render_actions

FOLDER = "human-manual-conflict-review"
HTML = "lightup-lab-human-conflict-choices-private.html"
CSV = "lightup-lab-human-conflict-decisions-private.csv"
CONTEXT = "lightup-lab-human-conflict-source-context.json"
ACTION_CSV = "lightup-lab-human-manual-conflict-actions-private.csv"
GUIDE = "START-HERE-MANUAL-CONFLICT-PRIVATE.txt"
STYLE = (
    "body{max-width:1000px;padding:1rem;margin:1.4rem auto;"
    "background:#f3f6fa;color:#182b42;font:15px/1.5 system-ui,sans-serif}"
    "section{background:#fff;border:1px solid #c9d7e5;border-radius:.6rem;"
    "padding:1rem;margin:1.1rem 0}"
    ".hold{border-left:6px solid #9a5b18;background:#fff1df;padding:1rem;font-weight:800}"
    "table{border-collapse:collapse;width:100%}td,th{border:1px solid #c6d5e2;"
    "padding:.6rem;text-align:left}th{background:#e8f0fa}"
)


def render_decisions(ledger: bytes, role_by_slot: dict[int, str]) -> bytes:
    try:
        rows = list(csv.reader(io.StringIO(ledger.decode("utf-8"), newline=""), strict=True))
    except (ValueError, UnicodeError, csv.Error) as exc:
        raise Hold("invalid native HUMAN manual conflict decision ledger") from exc
    if not rows or len(rows[0]) != 5:
        raise Hold("invalid HUMAN manual conflict decision columns")
    entries = rows[1:]
    table = []
    for row in entries:
        if len(row) != 5 or not row[0].isdecimal():
            raise Hold("invalid original HUMAN manual selection record")
        slot = int(row[0])
        role = role_by_slot.get(slot)
        if role is None:
            raise Hold("original HUMAN role choice exceeds source")
        table.append((slot, role, *row[1:]))
    tr = "".join("<tr>" + "".join("<td>" + escape(str(cell)) + "</td>"
                                     for cell in item) + "</tr>" for item in table)
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        + "script-src 'none'; style-src 'sha256-" + style_hash +
        "'; connect-src 'none'; img-src 'none'; base-uri 'none'; object-src 'none'\">"
        "<title>LightUp PRIVATE HUMAN manual conflict decisions</title>"
        "<style>" + STYLE + "</style></head><body>"
        "<h1>PRIVATE HUMAN manual conflict decisions</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD ·"
        " REVIEW_ONLY · NO AUTHORITY</p>"
        "<section><p>" + str(len(entries)) + " overlapping original local"
        " HUMAN slots had an explicit owner-side source choice. No"
        " automatic precedence or recipient identity proof occurred."
        " This view contains NO original endpoint URLs, private notes,"
        " filesystem paths or reviewer identities.</p></section>"
        "<section><table><thead><tr><th>Original slot</th><th>Suggested role</th>"
        "<th>Chosen source packet</th><th>Eligible original packets</th>"
        "<th>Chosen HUMAN stage</th><th>Private note changed?</th></tr>"
        "</thead><tbody>" + tr + "</tbody></table></section>"
        "<p>This is an unsigned, owner-private original-source consistency"
        " summary. It is NOT identity, remediation evidence, consent, scope,"
        " an assessment dispatch, or HUMAN GO.</p></body></html>"
    ).encode("utf-8")


def human_actions(packets, rounds, worksheet):
    covered = {index for _directory, _work, indices in packets for index in indices}
    choices = {
        "NEEDS_INPUT": "COLLECT_MISSING_HUMAN_INPUT",
        "HUMAN_REVIEW": "SCHEDULE_HUMAN_REVIEW",
        "FOLLOW_UP": "FOLLOW_UP_WITH_HUMAN_OWNER",
    }
    rows = []
    for index, (prior, after) in enumerate(
            zip(rounds[-1]["human_rows"], worksheet["human_rows"])):
        received = index in covered
        rows.append((
            index + 1, prior["role"],
            "ROLE_REPLY_RECEIVED" if received else "AWAITING_HUMAN_ROLE_REPLY",
            after["stage"],
            choices[after["stage"]] if received else "REQUEST_HUMAN_ROLE_REPLY",
            ("YES" if after["note"] != prior["note"] else "NO")
            if received else "NOT_RETURNED",
        ))
    rows.sort(key=lambda row: (0 if row[2] == "AWAITING_HUMAN_ROLE_REPLY" else 1,
                               0 if row[3] == "NEEDS_INPUT" else 1, row[0]))
    sink = io.StringIO(newline="")
    writer = csv.writer(sink, lineterminator="\n")
    writer.writerow(("original_slot", "suggested_human_role",
                     "private_human_reply_status", "latest_human_stage",
                     "suggested_operator_next_step", "private_note_changed"))
    writer.writerows(rows)
    return rows, sink.getvalue().encode("utf-8")


def admit_manual_resolution(result_dir, decision_file, return_dirs,
                            rounds, endpoints, digest):
    """Re-admit all original inputs AND exact complete resolved four-file packet."""
    if not 2 <= len(rounds) <= 8:
        raise Hold("manual role conflict requires 2-8 original HUMAN source rounds")
    if not decision_file or not return_dirs:
        raise Hold("manual conflict intake requires choice CSV and original role returns")
    packets = read_packets(return_dirs, rounds, endpoints, digest)
    source_fingerprint = source_set_digest(digest, rounds, packets)
    decision_bytes = require_private_file(decision_file, 32768)
    expected = resolve_files(rounds, endpoints, digest, packets,
                             source_fingerprint, decision_bytes)
    fd, absolute = open_output_directory(result_dir)
    try:
        if set(os.listdir(fd)) != set(RESOLVED):
            raise Hold("manual conflict result must have its exact original PRIVATE inventory")
        actual = {name: read_private_bundle_item(fd, name, LIMIT) for name in RESOLVED}
    finally:
        os.close(fd)
    if actual != expected:
        raise Hold("resolved HUMAN packet differs from original source and explicit choices")
    worksheet = load_json(expected[RESOLVED[0]])
    validate_worksheet(worksheet, digest, len(endpoints))
    role_by_slot = {index: record["role"]
                    for index, record in enumerate(rounds[-1]["human_rows"], start=1)}
    html = render_decisions(expected[CSV], role_by_slot)
    actions, action_csv = human_actions(packets, rounds, worksheet)
    action_html = render_actions(actions)
    guide = (
        "LIGHTUP PRIVATE HUMAN MANUAL CONFLICT REVIEW\n"
        "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO AUTHORITY\n"
        "The owner selected one original role-return packet per conflicted slot.\n"
        "All other slots preserve original or uniquely selected HUMAN content.\n"
        "This directory contains ONLY an ordinal/role summary, an exact owner\n"
        "choice ledger and source context, plus a source-minimal owner action\n"
        "worklist (private HTML and CSV), not a duplicate full HUMAN worksheet.\n"
        "Source and receipt do NOT prove recipient identity or consent.\n"
        "Re-open the workroom with all original return dirs, original manual\n"
        "choice CSV and exact original conflict result dir, in the same order.\n"
        "No scan, assessment, authorization, network or HUMAN GO occurred.\n"
    ).encode("utf-8")
    artifacts = {HTML: html, CSV: expected[CSV], CONTEXT: expected[RESOLVED[1]],
                 ACTION_HTML: action_html, ACTION_CSV: action_csv, GUIDE: guide}
    if any(not 0 < len(item) <= LIMIT for item in artifacts.values()):
        raise Hold("source-bound manual conflict review exceeded PRIVATE file capacity")
    return absolute, worksheet, artifacts
