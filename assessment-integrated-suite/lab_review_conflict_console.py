#!/usr/bin/env python3
"""Foreground original HUMAN per-ordinal conflict decisions, no source execution."""
from __future__ import annotations

import lab_plan_review_console
import lab_review_conflict_resolution as conflict
import lab_review_team_handoff as handoff


def prepare(session, path_prompt, ask, *, publish: bool = False) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    final = path_prompt("Unchanged original finalized 0700 HUMAN Lab room")
    team_handoff = path_prompt("Unchanged original 0700 assigned HUMAN team handoff")
    root = path_prompt("Original 0700 source-bound PRIVATE HUMAN multi-team batch")
    count = ask("Previously saved private HUMAN continuations to re-admit (0–6)", "0")
    if count not in tuple(map(str, range(7))):
        print("HOLD: choose at most six earlier original HUMAN continuation rooms.")
        return
    history = [
        path_prompt(f"Original PRIVATE HUMAN continuation #{i} (oldest first)")
        for i in range(1, int(count) + 1)
    ]
    replies_count = ask("New HUMAN team responses to review (1–4)", "1")
    if replies_count not in ("1", "2", "3", "4"):
        print("HOLD: only 1–4 original HUMAN teams at once.")
        return
    replies = []
    for i in range(int(replies_count)):
        team = ask(f"Original assigned HUMAN team #{i+1}")
        if team not in handoff.SLUGS or team in {x[0] for x in replies}:
            print("HOLD: original HUMAN team must be distinct and assigned.")
            return
        filename = path_prompt(f"Owner-private complete {team} returned HUMAN CSV")
        replies.append((team, filename))
    choice_room, completed = "", ""
    if publish:
        choice_room = path_prompt("Existing original PRIVATE per-ordinal choice room")
        completed = path_prompt("Completed owner-0600 HUMAN choice CSV")
    parent = path_prompt("Original owner-only 0700 output parent", session.parent)
    folder = ask("NEW UNUSED PRIVATE HUMAN decision folder",
                 "private-lab-human-conflict-resolved" if publish else
                 "private-lab-human-conflict-choices")
    print("This recomputes EVERY original source, prior HUMAN decision and")
    print("team reply. No stored HUMAN decision is silently overwritten.")
    print("No data is sent, scanned or finalized. New output is PRIVATE only.")
    confirm = ("PUBLISH PRIVATE HUMAN CONFLICT CANDIDATE" if publish
               else "PREPARE PRIVATE HUMAN CONFLICT CHOICES")
    if ask("Type " + confirm, "") != confirm:
        print("HOLD: original HUMAN conflict action cancelled.")
        return
    try:
        page = conflict.build(
            packets, final, team_handoff, root, tuple(history), replies,
            parent, folder, completed=completed, expected_room=choice_room)
    except Exception:
        print("HOLD: original source/PRIVATE HUMAN conflicts could not be admitted.")
        return
    session.parent = parent
    print("PRIVATE REVIEW_ONLY, not FINALIZED: " + str(page))
    print("Open complete output only on a trusted owner-private device.")
