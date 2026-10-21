#!/usr/bin/env python3
"""Create a NEW source-free HUMAN Attention v2 proposal from explicitly selected original revisions.

Offline / original receipt re-admission / withhold-by-default. NEVER a task grant,
authentic actor assignment, scanner, real assessment, target or consent.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import os
from pathlib import Path
import sys

import attention_history as history
import attention_receipt as attention
import lab_route_handoff as original
from operator_navigation import ACTIONS

SCHEMA = "lightup.private.human-lab-attention.explicit-next.v1"
RECEIPT_SCHEMA = "lightup.private.human-lab-attention.explicit-next-receipt.v1"
CHOICES_SOURCE = "PRIVATE-ORIGINAL-EDITED-HUMAN-CHOICES.csv"
NEXT = "PRIVATE-NEXT-HUMAN-ATTENTION.json"
MATRIX = "PRIVATE-SELECTED-HUMAN-CHOICES.csv"
VIEW = "OPEN-PRIVATE.html"
RECEIPT = "PRIVATE-RECEIPT.json"
INPUT_LIMIT = 8192


def _read_choices(filename: str, revision_count: int) -> tuple[bytes, list[tuple[int, int]]]:
    raw = original._read(Path(filename), INPUT_LIMIT)
    try:
        decoded = raw.decode("utf-8", "strict")
        if "\ufeff" in decoded or "\x00" in decoded:
            raise ValueError("encoding")
        rows = list(csv.reader(io.StringIO(decoded, newline=""), strict=True))
    except (UnicodeError, ValueError, csv.Error):
        raise original.Hold("HOLD: original HUMAN choice worksheet must be strict UTF-8 CSV") from None
    if len(rows) != len(original.ORDER) + 1 or rows[0] != [
            "action", "role_from_revision", "followup_from_revision"]:
        raise original.Hold("HOLD: original twenty-row HUMAN choice worksheet is incomplete")
    selections = []
    for expected, row in zip(original.ORDER, rows[1:]):
        if (len(row) != 3 or row[0] != str(expected)
                or any(len(value) != 1 or value not in "012345678"
                       for value in row[1:])):
            raise original.Hold("HOLD: source-free HUMAN action/selection invalid or reordered")
        role_from, followup_from = map(int, row[1:])
        if role_from > revision_count or followup_from > revision_count:
            raise original.Hold("HOLD: a HUMAN selected revision does not exist")
        selections.append((role_from, followup_from))
    return raw, selections


def _build(route_rooms: list[str], attention_rooms: list[str], choice_path: str
           ) -> dict[str, bytes]:
    # History/portfolio cannot be reused without opening ALL original native
    # self-reports and ALL original received Attention source bytes first.
    original_attention_rooms, entries = history._inputs(route_rooms, attention_rooms)
    raw, selections = _read_choices(choice_path, len(entries))
    latest_raw = entries[-1]["source"]
    # Already accepted by the original attention native v2 strict admission.
    latest = original._parse(latest_raw)
    if not original._exact(latest, attention.ATTENTION_FIELDS):
        raise original.Hold("HOLD: latest original native Attention schema changed")
    newer = dict(latest)
    actions = []
    selected_rows = [[
        "action", "last_self_reported_state", "selected_role_revision",
        "selected_followup_revision", "proposed_role", "proposed_human_followup", "authority"
    ]]
    counts = {"role_explicitly_selected": 0, "followup_explicitly_selected": 0,
              "role_withheld": 0, "followup_withheld": 0}
    for idx, number in enumerate(original.ORDER):
        rno, fno = selections[idx]
        candidate = dict(entries[-1]["rows"][idx])
        candidate["proposed_role"] = (
            entries[rno - 1]["rows"][idx]["proposed_role"] if rno else "UNASSIGNED"
        )
        candidate["proposed_human_followup"] = (
            entries[fno - 1]["rows"][idx]["proposed_human_followup"] if fno else "UNCLASSIFIED"
        )
        # No free text, external source, customer note, task recipient or
        # unverified real source record can be selected into this proposal.
        if candidate["proposed_role"] not in attention.ROLES or (
                candidate["proposed_human_followup"] not in attention.FOLLOWUPS):
            raise original.Hold("HOLD: unknown original HUMAN role/follow-up")
        counts["role_explicitly_selected" if rno else "role_withheld"] += 1
        counts["followup_explicitly_selected" if fno else "followup_withheld"] += 1
        actions.append(candidate)
        selected_rows.append([
            number, candidate["self_reported_state"], rno, fno,
            candidate["proposed_role"], candidate["proposed_human_followup"], "REVIEW_ONLY",
        ])
    newer["steps"] = actions
    next_bytes = original._json(newer)
    # Re-admit this exact native-created source-free v2 proposal using the
    # existing trusted original self-report state admission logic.
    states, _ = attention._rooms(route_rooms)
    attention._admit(next_bytes, states)

    rows_html = "".join(
        "<tr><td>" + str(row[0]) + "</td><td>" +
        html.escape(ACTIONS[str(row[0])]) + "</td><td>" +
        html.escape(str(row[1])) + "</td><td>" +
        str(row[2]) + "</td><td>" + str(row[3]) + "</td><td>" +
        html.escape(str(row[4])) + "</td><td>" +
        html.escape(str(row[5])) + "</td></tr>"
        for row in selected_rows[1:]
    )
    page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';script-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none'">
<title>PRIVATE HUMAN explicitly selected attention continuation</title>
<style>:root{color-scheme:dark;background:#0b2135;color:#f0f8ff;font:16px/1.55 system-ui}
body{max-width:1280px;margin:auto;padding:24px}header,section,footer{padding:24px;
margin:18px 0;border:1px solid #688ca4;background:#1d3b53}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:9px;border-bottom:1px solid #5c7991}
.notice{color:#ffe0a4;font-weight:700}a{color:#caeaff}
@media print{body{background:white;color:black}header,section,footer{background:white}}
</style><header><h1>PRIVATE HUMAN Attention · new explicit continuation proposal</h1>
<p class="notice">REVIEW_ONLY · Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD</p>
<p>Each role/follow-up cell was explicitly withheld (0) or chosen from
an independently reopened original HUMAN proposal receipt revision 1–""" +
            str(len(entries)) + """. The chosen numbers are manual file
order, never proven time. A withheld cell becomes UNASSIGNED or UNCLASSIFIED.
This is not a real assignment, authenticated review or consent.</p>
<p><a href="PRIVATE-NEXT-HUMAN-ATTENTION.json">Reopen source-free v2 HUMAN draft in the offline browser</a>
after reloading the SAME original source-free Lab Route reports in the SAME
operator-selected order. This still needs manual HUMAN confirmation.</p></header>
<section><h2>All twenty original HUMAN action proposals</h2>
<table><thead><tr><th>Action</th><th>Original caption</th><th>Last self-report</th>
<th>Role from revision (0=withheld)</th><th>Follow-up from revision (0=withheld)</th>
<th>Proposed role</th><th>Proposed HUMAN follow-up</th></tr></thead>
<tbody>""" + rows_html + """</tbody></table></section>
<footer><p>All genuine authority flags remain FALSE. This unsigned original
source-free HUMAN draft is not a native finding, reviewer identity,
authenticated chronology, delegated instruction, consent, grant, scan,
external dispatch, task completion or release. Existing exact-head CI,
owner and independent browser/security/privacy reviews, scope gates,
current separately authenticated client+operator consent with action-time
revocation and explicit HUMAN GO remain mandatory.</p></footer></html>""").encode("utf-8")

    summary = original._json({
        "schema": SCHEMA, "mode": "REVIEW_ONLY", "authority": dict(original.FALSE_AUTH),
        "revision_count": len(entries),
        "source_authenticated": False, "reviewer_identity_verified": False,
        "chronology_verified": False, "role_assigned": False,
        "work_executed": False, "consent_verified": False, "release_allowed": False,
        "original_actions": list(original.ORDER),
        "explicit_decision_counts": counts,
        "originating_attention_source_sha256_unsigned": [
            entry["source_sha256_unsigned"] for entry in entries
        ],
        "next_source_free_human_proposal_sha256_unsigned": hashlib.sha256(next_bytes).hexdigest(),
    })
    files = {
        CHOICES_SOURCE: raw, NEXT: next_bytes,
        MATRIX: original._csv(selected_rows),
        VIEW: page, "PRIVATE-DECISIONS.json": summary,
    }
    files[RECEIPT] = original._json({
        "schema": RECEIPT_SCHEMA, "mode": "REVIEW_ONLY",
        "authority": dict(original.FALSE_AUTH),
        "actor_authenticated": False, "consent_verified": False,
        "human_go": False, "scan_authorized": False,
        "role_assigned": False, "release_allowed": False,
        "files": {
            name: {"bytes": len(contents),
                   "sha256_unsigned": hashlib.sha256(contents).hexdigest()}
            for name, contents in sorted(files.items())
        },
    })
    return files


def create(route_rooms: list[str], attention_rooms: list[str],
           history_room: str, choice_path: str,
           private_parent: str, folder: str) -> Path:
    # The history room is a fully admitted original PRIVATE input, not
    # arbitrary user-supplied search state; never modify source rooms.
    history.reopen(route_rooms, attention_rooms, history_room)
    originals = [
        original._private_dir(Path(p))
        for p in [*route_rooms, *attention_rooms, history_room]
    ]
    choices_file = Path(choice_path)
    originals.append(original._private_dir(choices_file.parent))
    parent = original._private_dir(Path(private_parent))
    if any(parent == p or p in parent.parents for p in originals):
        raise original.Hold("HOLD: HUMAN continuation cannot write inside original/private inputs")
    if choices_file == Path(history_room) / history.CHOICES:
        raise original.Hold("HOLD: copy and edit HUMAN choice sheet OUTSIDE saved original portfolio")
    files = _build(route_rooms, attention_rooms, choice_path)
    return original._write_room(str(parent), folder, files)


def reopen(route_rooms: list[str], attention_rooms: list[str],
           history_room: str, choice_path: str, saved_room: str) -> None:
    history.reopen(route_rooms, attention_rooms, history_room)
    expected = _build(route_rooms, attention_rooms, choice_path)
    saved = original._private_dir(Path(saved_room))
    if set(os.listdir(saved)) != set(expected):
        raise original.Hold("HOLD: unexpected, altered or missing HUMAN continuation files")
    for name, raw in expected.items():
        if original._read(saved / name, 524288) != raw:
            raise original.Hold("HOLD: source-bound HUMAN continuation output bytes changed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    create_parser = sub.add_parser("create", help="Publish a NEW unsigned HUMAN v2 continuation draft")
    reopen_parser = sub.add_parser("reopen", help="Reopen exact original HUMAN attention continuation")
    for command in (create_parser, reopen_parser):
        command.add_argument("--route-rooms", nargs="+", required=True)
        command.add_argument("--attention-rooms", nargs="+", required=True)
        command.add_argument("--history-room", required=True)
        command.add_argument("--edited-choices", required=True)
    create_parser.add_argument("--private-parent", required=True)
    create_parser.add_argument("--folder", required=True)
    reopen_parser.add_argument("--saved-room", required=True)
    args = parser.parse_args()
    try:
        if args.mode == "create":
            room = create(args.route_rooms, args.attention_rooms,
                          args.history_room, args.edited_choices,
                          args.private_parent, args.folder)
            print("New PRIVATE HUMAN v2 proposal:", room / NEXT)
            print("Scriptless HUMAN selection workroom:", room / VIEW)
        else:
            reopen(args.route_rooms, args.attention_rooms,
                   args.history_room, args.edited_choices, args.saved_room)
            print("Exact original PRIVATE HUMAN selection and output bytes reopened.")
        print("REVIEW_ONLY / DRAFT-HOLD. Not real source, recipient, scanner, role assignment or consent.")
        return 2
    except (original.Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, original.Hold)
              else "HOLD: source-bound PRIVATE HUMAN continuation cannot be admitted",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
