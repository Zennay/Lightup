#!/usr/bin/env python3
"""Offline minimal-necessary PRIVATE per-HUMAN action handoff, never dispatch.

Reads original native action results, re-admits original source chain, choices
and action CSV byte identity, then creates a new owner-private workroom.
"""
from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path
import shutil
import sys

from history_actions import admit_team, admission, open_context, template_rows, MAX_ACTION_CSV
from history_team import literal_false_authority, private_parent_for_originals
from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    object_unique, read_owner_file, reject, safe_human, write_private,
)


def admitted_original(args):
    source_context_raw = read_owner_file(args.action_context, MAX_MANIFEST)
    source_context = open_context(source_context_raw)
    case = admit_team(
        source_context["original_team_context"],
        source_context["original_team_choice"],
        source_context["original_team_csv"],
    )
    if (
        digest(case["context_raw"]) != source_context["original_team_context_sha256"] or
        case["choice_sha"] != source_context["original_team_choice_sha256"] or
        case["csv_sha"] != source_context["original_team_csv_sha256"]
    ):
        reject("PRIVATE HOLD: source/original reviewer changed since action plan creation")
    raw_plan = read_owner_file(args.plan, MAX_ACTION_CSV)
    rows = admission(raw_plan, template_rows(case))
    raw_packet = read_owner_file(args.actions, MAX_MANIFEST)
    try:
        packet = json.loads(
            raw_packet.decode("utf-8"), object_pairs_hook=object_unique,
            parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite original action packet"),
        )
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: unreadable original action packet") from exc
    if (
        not isinstance(packet, dict) or set(packet) != {
            "schema", "authority", "sources_reopened", "historical_only",
            "actions_dispatched", "context_sha256", "human_action_plan_sha256", "rows"
        } or packet["schema"] != "lightup.private.workspace-ledger-actions-human.v1" or
        not literal_false_authority(packet["authority"]) or
        packet["sources_reopened"] is not False or
        packet["historical_only"] is not True or
        packet["actions_dispatched"] is not False or
        packet["context_sha256"] != digest(source_context_raw) or
        packet["human_action_plan_sha256"] != digest(raw_plan) or
        packet["rows"] != rows or
        raw_packet != canonical(packet)
    ):
        reject("PRIVATE HOLD: finalized HUMAN action packet not identical to original plan")
    return {
        "source_context": source_context_raw,
        "sources": case["sources"],
        "action_packet": raw_packet,
        "action_plan": raw_plan,
        "rows": rows,
    }


def render_private(owner, rows):
    body = [
        "<p><strong>PRIVATE HUMAN PROPOSALS ONLY.</strong> No real task was sent, "
        "booked, granted or approved. Original customer files are not reopened. "
        "This locally authored owner label is NOT authenticated recipient identity. "
        "Check actual recipient and disclosure authority separately before sharing.</p>",
        "<p>Locally selected proposed HUMAN owner: <strong>" + html.escape(owner) + "</strong>. "
        "Only owner-matched manually proposed entries are included. Nothing from "
        "other proposed owners has been copied into this report.</p>",
        "<table><thead><tr><th>Original kit</th><th>Transition</th>"
        "<th>Proposal state</th><th>HUMAN priority</th><th>Proposed day</th>"
        "<th>Next HUMAN step</th></tr></thead><tbody>",
    ]
    for row in rows:
        body.append(
            "<tr><td>" + str(row["kit_ordinal"]) + "</td><td>" +
            str(row["transition"]) + "</td><td>" +
            html.escape(row["action_status"]) + "</td><td>" +
            html.escape(row["human_priority"]) + "</td><td>" +
            html.escape(row["proposed_day"]) + "</td><td>" +
            html.escape(row["next_human_step"]) + "</td></tr>"
        )
    body.append(
        "</tbody></table><p>All original work is HUMAN-only and source-record "
        "byte-bound, NOT a verified vulnerability, remediation, client consent, "
        "scope grant, retest or automatic notification. Original source/recipient "
        "claims are unsigned. Follow-up and suggested day are unbooked.</p>"
    )
    return html_page("LightUp PRIVATE minimum-necessary HUMAN owner brief", "".join(body))


def run(args):
    if any(not isinstance(v, str) or not os.path.isabs(v) or
           os.path.normpath(v) != v for v in
           (args.action_context, args.actions, args.plan)):
        reject("PRIVATE HOLD: original files must have canonical absolute paths")
    owner = safe_human(args.owner, 80)
    if not owner or owner != owner.strip():
        reject("PRIVATE HOLD: an exact non-empty HUMAN owner is required")
    original = admitted_original(args)
    selected = [
        row for row in original["rows"]
        if row["accountable_human"] == owner and
           row["action_status"] != "unassigned"
    ]
    if not selected:
        reject("PRIVATE HOLD: no explicit source-bound HUMAN work for this exact owner")
    dest = private_parent_for_originals(args.private_parent, original["sources"])
    # Reopen archived original ledgers, reviewer decisions and private action
    # packet after selecting owner so changed input never results in handoff.
    refreshed = admitted_original(args)
    if (
        refreshed["source_context"] != original["source_context"] or
        refreshed["action_packet"] != original["action_packet"] or
        refreshed["action_plan"] != original["action_plan"]
    ):
        reject("PRIVATE HOLD: original HUMAN source bytes changed during local selection")
    record = {
        "schema": "lightup.private.workspace-ledger-owner-brief.v1",
        "authority": FLAGS,
        "human_only": True,
        "sources_reopened": False,
        "actions_dispatched": False,
        "recipient_authenticated": False,
        "owner_label": owner,
        "original_human_actions_sha256": digest(original["action_packet"]),
        "original_action_plan_sha256": digest(original["action_plan"]),
        "selected": selected,
    }
    directory = new_private(dest)
    try:
        write_private(directory, "PRIVATE-HUMAN-owner-brief.json", canonical(record))
        write_private(directory, "PRIVATE-HUMAN-owner-brief.html", render_private(owner, selected))
        write_private(directory, "OPEN-PRIVATE.html", html_page(
            "LightUp PRIVATE selected HUMAN owner handoff",
            "<p>Minimum-necessary private local selected HUMAN owner work. "
            "No recipient authenticated, source scan, actual dispatched task or "
            "original customer material shared.</p>"
            "<p><a href='PRIVATE-HUMAN-owner-brief.html'>Open original-owner PRIVATE HUMAN brief</a>. "
            "Operator must check real recipient identity and disclosure permission "
            "separately. This local document itself grants none.</p>"
        ))
    except BaseException:
        shutil.rmtree(directory)
        raise
    print("PRIVATE HOLD: owner-specific HUMAN proposal workroom only; nothing sent or granted")
    print(str(Path(directory) / "OPEN-PRIVATE.html"))
    return 3


def main():
    p = argparse.ArgumentParser(
        description="PRIVATE single-HUMAN owner handoff from exact finalized original actions"
    )
    p.add_argument("--action-context", required=True)
    p.add_argument("--actions", required=True)
    p.add_argument("--plan", required=True)
    p.add_argument("--owner", required=True, help="Exact HUMAN name from original finalized actions")
    p.add_argument("--private-parent", required=True, help="Existing 0700 destination outside checkout")
    args = p.parse_args()
    try:
        return run(args)
    except (Hold, OSError, UnicodeError, ValueError, TypeError):
        print("PRIVATE HOLD: cannot safely prepare source-locked HUMAN owner brief", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
