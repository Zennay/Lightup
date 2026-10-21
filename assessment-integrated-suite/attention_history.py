#!/usr/bin/env python3
"""Compare ORIGINAL source-bound PRIVATE HUMAN Attention receipt revisions.

READ-ONLY originals / no client source, real task ownership, scan, grant or consent.
Operator-selected revision order is NOT verified chronology.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import os
from pathlib import Path
import sys

import attention_receipt as attention
import lab_route_handoff as original
from operator_navigation import ACTIONS, LAB_STAGES

SCHEMA = "lightup.private.human-lab-attention.history.v1"
RECEIPT_SCHEMA = "lightup.private.human-lab-attention.history-receipt.v1"
HISTORY = "PRIVATE-HUMAN-ATTENTION-HISTORY.json"
MATRIX = "PRIVATE-HUMAN-ATTENTION-MATRIX.csv"
CHANGES = "PRIVATE-HUMAN-ATTENTION-CHANGES.csv"
VIEWER = "OPEN-PRIVATE.html"
LATEST = "PRIVATE-LATEST-HUMAN-ATTENTION.json"
CHOICES = "PRIVATE-EDITABLE-HUMAN-CHOICES.csv"
RECEIPT = "PRIVATE-RECEIPT.json"
FALSE_AUTH = dict(original.FALSE_AUTH)


def _inputs(route_rooms: list[str], attention_rooms: list[str]):
    if not 2 <= len(attention_rooms) <= 8:
        raise original.Hold("HOLD: two to eight saved ORIGINAL attention receipt rooms required")
    source_rooms = [original._private_dir(Path(room)) for room in route_rooms]
    if not 1 <= len(source_rooms) <= 8 or len(set(source_rooms)) != len(source_rooms):
        raise original.Hold("HOLD: one to eight distinct saved original HUMAN Route receipts required")
    revisions = [original._private_dir(Path(room)) for room in attention_rooms]
    if len(set(revisions)) != len(revisions):
        raise original.Hold("HOLD: repeated saved PRIVATE Attention room")
    if any(r in source_rooms for r in revisions):
        raise original.Hold("HOLD: original route and attention receipts cannot alias")

    states, _ = attention._rooms(route_rooms)
    entries = []
    seen = set()
    for number, room in enumerate(revisions, 1):
        source = room / attention.SOURCE
        # The existing native receipt's complete source -> output chain MUST
        # be reconstructed BEFORE a revision enters the comparison.
        attention.reopen(str(source), route_rooms, str(room))
        raw = original._read(source, attention.MAX_ATTENTION)
        raw_hash = hashlib.sha256(raw).hexdigest()
        if raw_hash in seen:
            raise original.Hold("HOLD: identical original HUMAN proposal repeated as a revision")
        seen.add(raw_hash)
        rows = attention._admit(raw, states)
        native_receipt = original._read(room / attention.RECEIPT, 262144)
        entries.append({
            "declared_revision": number,
            "source_sha256_unsigned": raw_hash,
            "source_bytes": len(raw),
            "receipt_sha256_unsigned": hashlib.sha256(native_receipt).hexdigest(),
            "receipt_bytes": len(native_receipt),
            "rows": rows,
            "source": raw,
        })
    return revisions, entries


def _table_rows(entries: list[dict[str, object]]) -> tuple[list[list[object]], list[list[object]]]:
    header = ["original_action", "stage", "last_self_reported_state"]
    for i in range(1, len(entries) + 1):
        header += ["revision_" + str(i) + "_proposed_role",
                   "revision_" + str(i) + "_proposed_followup"]
    matrix = [header]
    changes = [[
        "declared_revision", "original_action", "original_stage",
        "changed_field", "from_proposal", "to_proposal", "review_only",
    ]]
    for row_index, number in enumerate(original.ORDER):
        stage = next(title for title, _, options, _ in LAB_STAGES if str(number) in options)
        row = [number, stage, entries[-1]["rows"][row_index]["self_reported_state"]]
        for i, entry in enumerate(entries):
            item = entry["rows"][row_index]
            row.extend([item["proposed_role"], item["proposed_human_followup"]])
            if i:
                previous = entries[i - 1]["rows"][row_index]
                for key in ("proposed_role", "proposed_human_followup"):
                    if item[key] != previous[key]:
                        changes.append([
                            i + 1, number, stage, key,
                            previous[key], item[key], "REVIEW_ONLY",
                        ])
        matrix.append(row)
    return matrix, changes


def _stage_summary(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    latest = entries[-1]["rows"]
    result = []
    for stage, _, ids, _ in LAB_STAGES:
        chosen = [latest[int(id_) - original.ORDER[0]] for id_ in ids]
        result.append({
            "original_stage": stage,
            "original_actions": len(chosen),
            "last_revision_needs_input": sum(row["self_reported_state"] == "NEEDS_INPUT" for row in chosen),
            "last_revision_unassigned_roles": sum(row["proposed_role"] == "UNASSIGNED" for row in chosen),
            "last_revision_untriaged_followups": sum(row["proposed_human_followup"] == "UNCLASSIFIED" for row in chosen),
            "last_revision_requested_original_input": sum(row["proposed_human_followup"] == "NEEDS_ORIGINAL" for row in chosen),
        })
    return result


def _viewer(entries: list[dict[str, object]], matrix: list[list[object]],
            changes: list[list[object]], stages: list[dict[str, object]]) -> bytes:
    stage_rows = "".join(
        "<tr>" + "".join("<td>" + html.escape(str(v), quote=True) + "</td>" for v in
            [s["original_stage"], s["original_actions"],
             s["last_revision_needs_input"], s["last_revision_unassigned_roles"],
             s["last_revision_untriaged_followups"]]) + "</tr>"
        for s in stages
    )
    diffs = "".join(
        "<tr>" + "".join("<td>" + html.escape(str(v), quote=True) + "</td>" for v in row) + "</tr>"
        for row in changes[1:]
    )
    if not diffs:
        diffs = "<tr><td colspan='7'>No revised role/follow-up markers. No real work verified.</td></tr>"
    latest_rows = "".join(
        "<tr><td>" + str(row["action"]) + "</td><td>" +
        html.escape(ACTIONS[str(row["action"])]) + "</td><td>" +
        html.escape(row["self_reported_state"]) + "</td><td>" +
        html.escape(row["proposed_role"]) + "</td><td>" +
        html.escape(row["proposed_human_followup"]) + "</td></tr>"
        for row in entries[-1]["rows"]
    )
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';script-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none'">
<title>PRIVATE HUMAN Attention revision portfolio</title>
<style>:root{color-scheme:dark;background:#0e2133;color:#edf7ff;font:16px/1.55 system-ui}
body{max-width:1380px;margin:auto;padding:24px}
header,section,footer{padding:18px 23px;margin:18px 0;border:1px solid #6c8da5;background:#1a3348}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:9px;border-bottom:1px solid #536c82}
.warning{color:#ffde9f;font-weight:700}.wide{overflow-x:auto}a{color:#b9e7ff}
@media print{body{background:#fff;color:#000}header,section,footer{background:#fff}}</style>
<header><h1>PRIVATE HUMAN Attention · native original revision portfolio</h1>
<p class="warning">REVIEW_ONLY · Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD</p>
<p>""" + str(len(entries)) + """ ORIGINAL attention rooms independently reopened
against the same 1–8 original saved HUMAN Lab Route receipt rooms.
All native original bytes were read-only re-admitted. This does NOT
authenticate true actor, source, chronology, real task assignment,
client consent, completed work, a vulnerability or any approved scan.</p>
<p><a href="PRIVATE-HUMAN-ATTENTION-MATRIX.csv">Complete 20-action revision matrix (CSV)</a>
· <a href="PRIVATE-HUMAN-ATTENTION-CHANGES.csv">Only changed HUMAN proposal cells (CSV)</a>
· <a href="PRIVATE-LATEST-HUMAN-ATTENTION.json">Latest original v2 HUMAN proposal (source-free JSON)</a>
· <a href="PRIVATE-EDITABLE-HUMAN-CHOICES.csv">Copy HUMAN revision-choice worksheet to a NEW private input file (CSV)</a></p>
</header>
<section><h2>Last selected revision · original five-stage HUMAN attention</h2>
<div class="wide"><table><thead><tr><th>Original stage</th><th>Actions</th>
<th>Self-reported NEEDS_INPUT</th><th>Proposed role unassigned</th>
<th>HUMAN follow-up untriaged</th></tr></thead><tbody>""" + stage_rows + """</tbody></table></div></section>
<section><h2>Prepare explicit HUMAN continuation (no automatic choices)</h2><p>The editable CSV starts with both role and follow-up selection WITHHELD (0) for every one of the 20 original actions. Copy it OUTSIDE this original receipt room into a NEW 0600 file in an existing owner-only 0700 input directory. Enter the source revision number 1–8 for a role and/or follow-up, or leave 0 to withhold. Native 80 can create a NEW source-free proposal from these explicit HUMAN choices only after re-admitting this original saved portfolio and all its input receipts. No original receipt may be edited in place. This does not assign a human or grant authority.</p></section>
<section><h2>All proposal changes in manual order</h2><p>Role/follow-up changes
represent choices in supplied files, never proof of execution or elapsed time.</p>
<div class="wide"><table><thead><tr><th>Declared revision</th><th>Original action</th>
<th>Original stage</th><th>Field</th><th>Earlier proposal</th><th>Later proposal</th>
<th>Status</th></tr></thead><tbody>""" + diffs + """</tbody></table></div></section>
<section><h2>Complete last selected HUMAN proposal (all 20 original actions)</h2>
<div class="wide"><table><thead><tr><th>Action</th><th>Original caption</th>
<th>Original self-report</th><th>Proposed role</th><th>Proposed HUMAN follow-up</th>
</tr></thead><tbody>""" + latest_rows + """</tbody></table></div></section>
<footer><p>Each upstream original PRIVATE route and attention receipt was
reconstructed with the native 0700/0600 admission boundary. Outputs contain
only fixed HUMAN enums and original action captions; all authority flags
remain false. The last selected revision is not authenticated latest-in-time.
Original reviews, permanent named VPS and hosted CI, source-owner clearance,
independently authenticated current client+operator consent with revocation
at action time, unresolved scope issues and explicit HUMAN GO are separate.</p>
</footer></html>""").encode("utf-8")


def _files(entries: list[dict[str, object]]) -> dict[str, bytes]:
    matrix, changes = _table_rows(entries)
    summary = _stage_summary(entries)
    public_entries = [
        {key: value for key, value in e.items() if key not in ("rows", "source")}
        for e in entries
    ]
    history = original._json({
        "schema": SCHEMA, "mode": "REVIEW_ONLY", "authority": dict(FALSE_AUTH),
        "source_authenticated": False, "actor_authenticated": False,
        "original_source_verified": False, "time_order_verified": False,
        "consent_verified": False, "task_assigned": False,
        "task_execution_verified": False, "release_allowed": False,
        "round_order": "MANUALLY_ASSUMED", "revision_count": len(entries),
        "original_actions": list(original.ORDER),
        "source_free_revision_receipts": public_entries,
        "original_stage_summary": summary,
        "changed_proposal_cells": [
            {"declared_revision": r[0], "action": r[1], "original_stage": r[2],
             "changed_field": r[3], "previous": r[4], "next": r[5]}
            for r in changes[1:]
        ],
    })
    return {
        HISTORY: history,
        MATRIX: original._csv(matrix),
        CHANGES: original._csv(changes),
        VIEWER: _viewer(entries, matrix, changes, summary),
        LATEST: entries[-1]["source"],
        CHOICES: original._csv([["action", "role_from_revision", "followup_from_revision"]] +
                             [[action, 0, 0] for action in original.ORDER]),
    }


def _compose(route_rooms: list[str], attention_rooms: list[str]) -> dict[str, bytes]:
    _, entries = _inputs(route_rooms, attention_rooms)
    files = _files(entries)
    files[RECEIPT] = original._json({
        "schema": RECEIPT_SCHEMA, "mode": "REVIEW_ONLY",
        "authority": dict(FALSE_AUTH),
        "source_authenticated": False, "actor_authenticated": False,
        "consent_verified": False, "scan_authorized": False,
        "grant_authorized": False, "human_go": False,
        "saved_proposal_source_sha256_unsigned": [e["source_sha256_unsigned"] for e in entries],
        "original_attention_receipt_sha256_unsigned": [e["receipt_sha256_unsigned"] for e in entries],
        "files": {
            name: {"bytes": len(payload), "sha256_unsigned": hashlib.sha256(payload).hexdigest()}
            for name, payload in sorted(files.items())
        },
    })
    return files


def create(route_rooms: list[str], attention_rooms: list[str],
           private_parent: str, folder: str) -> Path:
    sources = [original._private_dir(Path(p)) for p in [*route_rooms, *attention_rooms]]
    parent = original._private_dir(Path(private_parent))
    if any(parent == path or path in parent.parents for path in sources):
        raise original.Hold("HOLD: revision portfolio cannot modify any source receipt")
    files = _compose(route_rooms, attention_rooms)
    return original._write_room(str(parent), folder, files)


def reopen(route_rooms: list[str], attention_rooms: list[str], saved_room: str) -> None:
    expected = _compose(route_rooms, attention_rooms)
    room = original._private_dir(Path(saved_room))
    if set(os.listdir(room)) != set(expected):
        raise original.Hold("HOLD: missing/extra PRIVATE HUMAN revision portfolio output files")
    for name, data in expected.items():
        if original._read(room / name, 524288) != data:
            raise original.Hold("HOLD: original source-bound PRIVATE HUMAN revision bytes changed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    create_parser = sub.add_parser("create", help="Create original receipt-bound private revision portfolio")
    reopen_parser = sub.add_parser("reopen", help="Reopen every ORIGINAL and output byte read-only")
    for command in (create_parser, reopen_parser):
        command.add_argument("--route-rooms", nargs="+", required=True,
                             help="1–8 original PRIVATE route receipt directories, manually ordered")
        command.add_argument("--attention-rooms", nargs="+", required=True,
                             help="2–8 ORIGINAL PRIVATE attention receipt rooms, manually ordered")
    create_parser.add_argument("--private-parent", required=True,
                               help="Existing 0700 owner-private parent, outside original source")
    create_parser.add_argument("--folder", required=True, help="New unused 0700 folder name")
    reopen_parser.add_argument("--saved-room", required=True, help="Existing PRIVATE revision output room")
    args = parser.parse_args()
    try:
        if args.mode == "create":
            path = create(args.route_rooms, args.attention_rooms, args.private_parent, args.folder)
            print("PRIVATE HUMAN revision portfolio:", path / VIEWER)
        else:
            reopen(args.route_rooms, args.attention_rooms, args.saved_room)
            print("PRIVATE HUMAN revision portfolio reopened from exact original bytes.")
        print("REVIEW_ONLY · not an assessment, authenticated chronology, consent or release.")
        return 2
    except (original.Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, original.Hold)
              else "HOLD: private HUMAN revision source could not be admitted",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
