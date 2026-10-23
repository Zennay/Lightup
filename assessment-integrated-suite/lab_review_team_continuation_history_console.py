#!/usr/bin/env python3
"""Foreground HUMAN-only history of original Lab batch plus continued rounds."""
from __future__ import annotations

import lab_plan_review_console
import lab_review_team_continuation_history


def prepare(session, path_prompt, ask) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    final = path_prompt("Original finalized 0700 HUMAN Lab review")
    handoff = path_prompt("Original 0700 source-bound HUMAN team handoff")
    root = path_prompt("Original 0700 PRIVATE multi-team batch")
    count = ask("Saved original HUMAN continuation rounds (1–7)", "2")
    if count not in tuple(map(str, range(1, 8))):
        print("HOLD: provide 1–7 distinct original HUMAN continuation rounds.")
        return
    rounds = [
        path_prompt(f"Previously saved 0700 HUMAN continuation #{i} (oldest first)")
        for i in range(1, int(count) + 1)
    ]
    parent = path_prompt("Existing owner-only 0700 PRIVATE output parent", session.parent)
    folder = ask("UNUSED source-bound HUMAN history folder",
                 "private-original-lab-human-continuation-history")
    print("The complete original root batch and every chained HUMAN continuation")
    print("are independently re-admitted before a NEW output is written.")
    print("The private dashboard contains only original ordinal/team/HUMAN stage,")
    print("note-changed Booleans and literal team inclusion changes.")
    print("Input order is not proof of dates, authorization or verified fixes.")
    if ask("Type BUILD ORIGINAL PRIVATE HUMAN CONTINUATION HISTORY", "") != (
            "BUILD ORIGINAL PRIVATE HUMAN CONTINUATION HISTORY"):
        print("HOLD: original HUMAN Lab chronology not published.")
        return
    try:
        page = lab_review_team_continuation_history.build(
            packets, final, handoff, root, rounds, parent, folder)
    except Exception:
        print("HOLD: original HUMAN Lab continuation chain could not re-admit.")
        return
    session.parent = parent
    print("PRIVATE REVIEW_ONLY: original HUMAN Lab history: " + str(page))
