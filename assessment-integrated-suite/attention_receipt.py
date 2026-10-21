#!/usr/bin/env python3
"""Receive and reopen an original PRIVATE HUMAN Attention proposal against native Lab Route receipts.

OFFLINE / REVIEW_ONLY: no original findings, target contact, assignment, grants or consent.
The saved browser proposal is an unsigned human self-report; no real reviewer or source is authenticated.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import os
from pathlib import Path
import sys

import lab_route_handoff as original
from operator_navigation import ACTIONS

SCHEMA = "lightup.private.human-lab-attention.v2"
RECEIPT_SCHEMA = "lightup.private.human-lab-attention.native-receipt.v1"
MAX_ATTENTION = 65536
SOURCE = "PRIVATE-ORIGINAL-HUMAN-ATTENTION.json"
NORMALIZED = "PRIVATE-HUMAN-ATTENTION.json"
CSV = "PRIVATE-HUMAN-ATTENTION.csv"
HTML = "OPEN-PRIVATE.html"
RECEIPT = "PRIVATE-RECEIPT.json"
ROLES = frozenset(("UNASSIGNED", "SOURCE_OWNER", "LAB_OPERATOR",
                   "SECURITY_REVIEWER", "PRIVACY_REVIEWER"))
FOLLOWUPS = frozenset(("UNCLASSIFIED", "NEEDS_ORIGINAL",
                       "HUMAN_DISCUSSION", "DEFERRED"))
FLAGS = dict(original.FALSE_AUTH)
ATTENTION_FIELDS = {
    "schema", "mode", "authority", "original_source_verified",
    "actual_work_verified", "consent_or_release_inferred",
    "source_files_included", "notes_included", "round_order",
    "round_count", "source_profiles", "steps",
}
ROW_FIELDS = {
    "action", "self_reported_state", "marker_transitions",
    "proposed_role", "proposed_human_followup",
}


def _rooms(paths: list[str]) -> tuple[list[tuple[str, ...]], list[dict[str, object]]]:
    if not 1 <= len(paths) <= 8:
        raise original.Hold("HOLD: choose 1–8 original PRIVATE HUMAN Lab Route receipt rooms")
    rooms = [original._private_dir(Path(p)) for p in paths]
    if len(set(rooms)) != len(rooms):
        raise original.Hold("HOLD: repeated HUMAN receipt room")
    states: list[tuple[str, ...]] = []
    source_profiles: list[dict[str, object]] = []
    for room in rooms:
        # Original native reopen checks EVERY saved file against the original
        # strict self-report source bytes; a browser-only export is insufficient.
        state = original.reopen(str(room))
        raw = original._read(room / original.ORIGINAL, original.MAX_INPUT)
        states.append(state)
        source_profiles.append({
            "original_self_report_sha256_unsigned": original._digest(raw),
            "original_self_report_bytes": len(raw),
        })
    return states, source_profiles


def _admit(raw: bytes, states: list[tuple[str, ...]]) -> list[dict[str, object]]:
    if not 0 < len(raw) <= MAX_ATTENTION:
        raise original.Hold("HOLD: bounded HUMAN proposal JSON required")
    data = original._parse(raw)  # duplicate JSON keys at any depth are HOLD
    if not original._exact(data, ATTENTION_FIELDS):
        raise original.Hold("HOLD: unknown HUMAN attention schema")
    if (data["schema"] != SCHEMA or data["mode"] != "REVIEW_ONLY"
            or data["original_source_verified"] is not False
            or data["actual_work_verified"] is not False
            or data["consent_or_release_inferred"] is not False
            or data["source_files_included"] is not False
            or data["notes_included"] is not False
            or data["round_order"] != "MANUALLY_ASSUMED"
            or type(data["round_count"]) is not int
            or data["round_count"] != len(states)
            or not original._exact(data["authority"], set(FLAGS))
            or any(data["authority"][k] is not False for k in FLAGS)):
        raise original.Hold("HOLD: HUMAN proposal claims authority, source or a different round count")
    expected_profiles = ["|".join(row) for row in states]
    if (type(data["source_profiles"]) is not list
            or data["source_profiles"] != expected_profiles):
        raise original.Hold("HOLD: HUMAN proposal does not match exact native source-free marker rounds")
    items = data["steps"]
    if type(items) is not list or len(items) != len(original.ORDER):
        raise original.Hold("HOLD: full twenty-action HUMAN proposal required")
    accepted: list[dict[str, object]] = []
    for index, (number, item) in enumerate(zip(original.ORDER, items)):
        actual = states[-1][index]
        changes = sum(states[n][index] != states[n - 1][index]
                      for n in range(1, len(states)))
        if (not original._exact(item, ROW_FIELDS)
                or type(item["action"]) is not int or item["action"] != number
                or type(item["self_reported_state"]) is not str
                or item["self_reported_state"] != actual
                or type(item["marker_transitions"]) is not int
                or item["marker_transitions"] != changes
                or type(item["proposed_role"]) is not str
                or item["proposed_role"] not in ROLES
                or type(item["proposed_human_followup"]) is not str
                or item["proposed_human_followup"] not in FOLLOWUPS):
            raise original.Hold("HOLD: HUMAN action, state, transition or fixed proposal category drift")
        accepted.append(dict(item))
    return accepted


def _normalized(rows: list[dict[str, object]], count: int) -> bytes:
    return original._json({
        "schema": "lightup.private.human-lab-attention.received.v1",
        "mode": "REVIEW_ONLY", "authority": dict(FLAGS),
        "original_source_verified": False, "actual_work_verified": False,
        "client_or_operator_authenticated": False,
        "consent_verified": False, "finding_verified": False,
        "scan_authorized": False, "release_allowed": False,
        "source_files_included": False, "round_count": count,
        "round_order": "MANUALLY_ASSUMED", "steps": rows,
    })


def _csv(rows: list[dict[str, object]]) -> bytes:
    return original._csv(
        [["action", "self_reported_state", "marker_transitions",
          "proposed_role", "proposed_human_followup", "authority"]] +
        [[r["action"], r["self_reported_state"], r["marker_transitions"],
          r["proposed_role"], r["proposed_human_followup"], "REVIEW_ONLY"]
         for r in rows]
    )


def _html(rows: list[dict[str, object]], count: int) -> bytes:
    parts = []
    for item in rows:
        number = item["action"]
        # Original captions come ONLY from unchanged native original ACTIONS.
        caption = ACTIONS[str(number)]
        cells = [str(number) + " · " + caption,
                 item["self_reported_state"],
                 str(item["marker_transitions"]),
                 item["proposed_role"],
                 item["proposed_human_followup"]]
        parts.append("<tr>" + "".join(
            "<td>" + html.escape(c, quote=True) + "</td>" for c in cells
        ) + "</tr>")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';script-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none'">
<title>PRIVATE HUMAN attention receipt · REVIEW_ONLY</title>
<style>:root{color-scheme:dark;background:#0e2233;color:#e8f5ff;font:16px/1.5 system-ui}
body{max-width:1180px;margin:auto;padding:24px}header,footer{padding:23px;background:#23374b;border:1px solid #61798e}
table{width:100%;border-collapse:collapse;margin:25px 0}
td,th{text-align:left;padding:11px;border-bottom:1px solid #56718a}
.warning{color:#fbdcad;font-weight:700}a{color:#c5ebff}@media print{body{background:#fff;color:#000}}
</style><header><h1>PRIVATE HUMAN attention · original marker-bound receipt</h1>
<p class="warning">REVIEW_ONLY · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD</p>
<p>""" + str(count) + """ manually ordered original PRIVATE HUMAN self-report receipt rooms
were re-admitted. This does NOT prove true chronology, operator identity,
source provenance, task completion, remediation, findings, consent or authority.
The role/follow-up fields are only locally written HUMAN proposals.</p>
<p><a href='PRIVATE-HUMAN-ROLES.html'>Open grouped HUMAN proposed-role workboard</a> (same PRIVATE room; no network)</p></header>
<table><thead><tr><th>Original action</th><th>Last human self-report</th>
<th>Changed markers*</th><th>Proposed role</th><th>Proposed follow-up</th></tr>
</thead><tbody>""" + "".join(parts) + """</tbody></table><footer>
<p>*Count only in the operator-selected file order, not real elapsed time.</p>
<p>No target, network, scanner, model, dispatch, assignment, client approval, grant
or live deployment. Original hosted and named permanent VPS CI, independent
privacy/security/browser/source-owner review, current separately authenticated
client/operator consent and action-time revocation, and explicit HUMAN GO
remain mandatory before release. An unsigned digest is not a signature.</p>
</footer></html>""").encode("utf-8")


ROLE_BOARD = "PRIVATE-HUMAN-ROLES.html"
ROLE_SUMMARY = "PRIVATE-HUMAN-ROLE-SUMMARY.json"


def _role_board(rows: list[dict[str, object]]) -> tuple[bytes, bytes]:
    """One strictly source-free, original twenty-action HUMAN attention cockpit."""
    groups = []
    sections = []
    for proposed_role in sorted(ROLES):
        items = [row for row in rows if row["proposed_role"] == proposed_role]
        needs = sum(item["self_reported_state"] == "NEEDS_INPUT" for item in items)
        open_rows = sum(item["self_reported_state"] != "DISCUSSED" for item in items)
        followups = {
            name: sum(item["proposed_human_followup"] == name for item in items)
            for name in sorted(FOLLOWUPS)
        }
        groups.append({
            "proposed_role": proposed_role,
            "human_proposals": len(items),
            "needs_original_input": needs,
            "not_marked_discussed": open_rows,
            "followup_category_counts": followups,
            "original_actions": [item["action"] for item in items],
        })
        lines = "".join(
            "<tr><td>" + str(item["action"]) + "</td><td>" +
            html.escape(ACTIONS[str(item["action"])]) + "</td><td>" +
            html.escape(item["self_reported_state"]) + "</td><td>" +
            html.escape(item["proposed_human_followup"]) +
            "</td></tr>" for item in items
        )
        sections.append(
            "<section><h2>" + html.escape(proposed_role) +
            " · " + str(len(items)) + " HUMAN proposals</h2>" +
            "<p>" + str(needs) + " self-reported needs original input; " +
            str(open_rows) + " not marked discussed. None assigned or verified.</p>" +
            "<table><thead><tr><th>Original action</th><th>Caption</th>" +
            "<th>Self-report</th><th>Proposed HUMAN follow-up</th></tr>" +
            "</thead><tbody>" + (lines or "<tr><td colspan='4'>No local proposals.</td></tr>") +
            "</tbody></table></section>"
        )
    data = original._json({
        "schema": "lightup.private.human-lab-attention.role-summary.v1",
        "mode": "REVIEW_ONLY", "authority": dict(FLAGS),
        "original_source_verified": False,
        "actor_authenticated": False, "role_assigned": False,
        "task_sent": False, "consent_verified": False,
        "real_work_completed": False,
        "groups": groups,
        "all_original_actions_included": len(rows) == len(original.ORDER),
    })
    page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';script-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none'">
<title>PRIVATE HUMAN role discussion board</title>
<style>:root{color-scheme:dark;background:#0b1e30;color:#f3f8fe;font:16px/1.5 system-ui}
body{max-width:1100px;margin:auto;padding:24px}
section,header{border:1px solid #637f95;padding:22px;background:#1b354b;margin:16px 0}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:10px;border-bottom:1px solid #60788c}
.warn{color:#f9d9a0;font-weight:700}a{color:#c5ebff}
@media print{body{background:#fff;color:#000}section,header{background:#fff}}
</style><header><h1>PRIVATE HUMAN proposed-role workboard</h1>
<p class="warn">REVIEW_ONLY · DRAFT/HOLD · PLAN/LAB ONLY</p>
<p>Five fixed role categories, including UNASSIGNED, derived only from
an exact native-received, source-free HUMAN marker/role proposal.
These are NOT real people, assigned tasks, messages, authorization,
verified remediation, original source authenticity, consent or releases.</p>
<p><a href='OPEN-PRIVATE.html'>Return to complete twenty-action HUMAN receipt</a> (same PRIVATE room; no network)</p>
</header>""" + "".join(sections) + """
<footer><p>No original client source, target, recipient address,
real action time or protected data included. Original HUMAN ordering
is not proven chronology. Security, original CI and explicit HUMAN GO
gates remain intact.</p></footer></html>""").encode("utf-8")
    return data, page


def _files(raw: bytes, rows: list[dict[str, object]], count: int) -> dict[str, bytes]:
    role_summary, role_board = _role_board(rows)
    return {
        SOURCE: raw,
        NORMALIZED: _normalized(rows, count),
        CSV: _csv(rows),
        HTML: _html(rows, count),
        ROLE_SUMMARY: role_summary,
        ROLE_BOARD: role_board,
    }


def _receipt(raw: bytes, files: dict[str, bytes],
             originals: list[dict[str, object]]) -> bytes:
    return original._json({
        "schema": RECEIPT_SCHEMA,
        "mode": "REVIEW_ONLY", "authority": dict(FLAGS),
        "source_verified": False, "actor_authenticated": False,
        "human_work_completed": False, "consent_verified": False,
        "scan_authorized": False, "grant_authorized": False,
        "release_allowed": False, "human_go": False,
        "round_order": "MANUALLY_ASSUMED",
        "original_self_report_rounds": originals,
        "saved_attention_source_sha256_unsigned": hashlib.sha256(raw).hexdigest(),
        "saved_attention_source_bytes": len(raw),
        "files": {
            name: {"bytes": len(payload),
                   "sha256_unsigned": hashlib.sha256(payload).hexdigest()}
            for name, payload in sorted(files.items())
        },
    })


def _compose(attention_path: str, room_paths: list[str]
             ) -> tuple[dict[str, bytes], list[tuple[str, ...]]]:
    states, provenances = _rooms(room_paths)
    raw = original._read(Path(attention_path), MAX_ATTENTION)
    rows = _admit(raw, states)
    files = _files(raw, rows, len(states))
    files[RECEIPT] = _receipt(raw, files, provenances)
    return files, states


def receive(attention_path: str, room_paths: list[str],
            private_parent: str, folder: str) -> Path:
    originals = [original._private_dir(Path(p)) for p in room_paths]
    target_parent = original._private_dir(Path(private_parent))
    if any(target_parent == path or path in target_parent.parents for path in originals):
        raise original.Hold("HOLD: output would modify an original HUMAN receipt room")
    files, _ = _compose(attention_path, room_paths)
    return original._write_room(str(target_parent), folder, files)


def reopen(attention_path: str, room_paths: list[str], saved_room: str) -> None:
    expected, _ = _compose(attention_path, room_paths)
    room = original._private_dir(Path(saved_room))
    if set(os.listdir(room)) != set(expected):
        raise original.Hold("HOLD: unexpected/missing PRIVATE HUMAN attention files")
    for name, payload in expected.items():
        if original._read(room / name, 262144) != payload:
            raise original.Hold("HOLD: original source-bound PRIVATE HUMAN attention bytes drifted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("receive", help="Create an exclusive 0700/0600 owner-private attention room")
    reopen_p = sub.add_parser("reopen", help="Reconstruct and re-admit ALL saved original bytes")
    for command in (create, reopen_p):
        command.add_argument("--attention", required=True,
                             help="Existing owner-only 0600 v2 browser HUMAN proposal JSON")
        command.add_argument("--rooms", nargs="+", required=True,
                             help="1-8 ORIGINAL native HUMAN route receipt directories, manually ordered")
    create.add_argument("--private-parent", required=True,
                        help="Existing owner-only 0700 output directory outside checkout")
    create.add_argument("--folder", required=True, help="New, unused private room name")
    reopen_p.add_argument("--saved-room", required=True, help="Previously received attention output room")
    args = parser.parse_args()
    try:
        if args.action == "receive":
            print(receive(args.attention, args.rooms, args.private_parent, args.folder))
            print("PRIVATE HUMAN attention received; all security authority remains false.")
        else:
            reopen(args.attention, args.rooms, args.saved_room)
            print("PRIVATE HUMAN attention reopened against original source-free receipt bytes.")
        print("REVIEW_ONLY / DRAFT-HOLD; no real original finding, consent or scan.")
        return 2
    except (original.Hold, ValueError, OSError) as exc:
        print(str(exc) if isinstance(exc, original.Hold)
              else "HOLD: original private HUMAN attention source could not be admitted",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
